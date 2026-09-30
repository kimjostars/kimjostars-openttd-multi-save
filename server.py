"""조별스서버 세이브본 아카이브용 로컬 백엔드."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DATABASE_PATH = DATA_DIR / "archive.sqlite3"
MAX_REQUEST_BYTES = 200 * 1024 * 1024
SESSION_SECONDS = 14 * 24 * 60 * 60
PASSWORD_ITERATIONS = 260_000
STATIC_FILES = {"/", "/index.html", "/mine.html", "/community.html", "/archive.css", "/archive.js"}


class ApiError(Exception):
    """클라이언트에 상태 코드와 메시지를 돌려주는 API 오류."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@contextmanager
def database():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL CHECK (scope IN ('mine', 'community')),
                owner_id TEXT NOT NULL REFERENCES users(id),
                parent_id TEXT REFERENCES folders(id),
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL CHECK (scope IN ('mine', 'community')),
                owner_id TEXT NOT NULL REFERENCES users(id),
                folder_id TEXT NOT NULL REFERENCES folders(id),
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS folders_scope_parent ON folders(scope, parent_id);
            CREATE INDEX IF NOT EXISTS files_scope_folder ON files(scope, folder_id);
            CREATE INDEX IF NOT EXISTS files_owner ON files(owner_id);
            """
        )


def password_digest(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"{PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded_digest: str) -> bool:
    try:
        iterations_text, salt_text, expected = encoded_digest.split("$", 2)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_text), int(iterations_text)
        ).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


class ArchiveRequestHandler(SimpleHTTPRequestHandler):
    """정적 페이지와 JSON API를 한 포트에서 제공하는 요청 핸들러."""

    server_version = "SaveArchive/1.0"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format_string: str, *args) -> None:
        # 로그인 토큰과 업로드 본문이 접근 로그에 남지 않도록 요청 경로만 기록합니다.
        print(f"[{self.log_date_time_string()}] {self.command} {urlsplit(self.path).path}")

    def send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def send_api_error(self, error: ApiError) -> None:
        self.send_json(error.status, {"error": error.message})

    def read_body(self, limit: int = MAX_REQUEST_BYTES) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ApiError(HTTPStatus.LENGTH_REQUIRED, "요청 크기를 확인할 수 없습니다.") from error
        if length <= 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "요청 내용이 비어 있습니다.")
        if length > limit:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "요청 파일은 최대 200 MiB까지 올릴 수 있습니다.")
        return self.rfile.read(length)

    def read_json(self) -> dict:
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON 요청이 필요합니다.")
        try:
            payload = json.loads(self.read_body(64 * 1024))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON 형식이 올바르지 않습니다.") from error
        if not isinstance(payload, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "요청 형식이 올바르지 않습니다.")
        return payload

    def current_user(self) -> sqlite3.Row | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        morsel = cookie.get("session")
        if morsel is None:
            return None

        token_hash = hashlib.sha256(morsel.value.encode("utf-8")).hexdigest()
        now = int(time.time())
        with database() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            return connection.execute(
                """
                SELECT users.id, users.username
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()

    def require_user(self) -> sqlite3.Row:
        user = self.current_user()
        if user is None:
            raise ApiError(HTTPStatus.UNAUTHORIZED, "로그인이 필요합니다.")
        return user

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with database() as connection:
            connection.execute(
                "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user_id, int(time.time()) + SESSION_SECONDS),
            )
        return token

    def json_response_with_session(self, user: sqlite3.Row, token: str) -> None:
        cookie = f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}"
        self.send_json(HTTPStatus.OK, {"authenticated": True, "username": user["username"]}, {"Set-Cookie": cookie})

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        try:
            if parsed.path == "/api/me":
                user = self.current_user()
                if user is None:
                    self.send_json(HTTPStatus.OK, {"authenticated": False})
                else:
                    self.send_json(HTTPStatus.OK, {"authenticated": True, "username": user["username"]})
                return
            if parsed.path == "/api/folders":
                self.get_folders(parse_qs(parsed.query))
                return
            if parsed.path == "/api/files":
                self.get_files(parse_qs(parsed.query))
                return
            match = re.fullmatch(r"/api/files/([0-9a-f-]+)/download", parsed.path)
            if match:
                self.download_file(match.group(1))
                return
            if parsed.path in STATIC_FILES:
                self.path = parsed.path
                super().do_GET()
                return
            raise ApiError(HTTPStatus.NOT_FOUND, "요청한 경로를 찾을 수 없습니다.")
        except ApiError as error:
            self.send_api_error(error)
        except Exception:
            self.log_error("GET 요청 처리 중 오류가 발생했습니다")
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "서버 오류가 발생했습니다."})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        try:
            if parsed.path == "/api/auth/register":
                self.register()
            elif parsed.path == "/api/auth/login":
                self.login()
            elif parsed.path == "/api/auth/logout":
                self.logout()
            elif parsed.path == "/api/folders":
                self.create_folder()
            elif parsed.path == "/api/files":
                self.upload_files()
            else:
                raise ApiError(HTTPStatus.NOT_FOUND, "요청한 경로를 찾을 수 없습니다.")
        except ApiError as error:
            self.send_api_error(error)
        except sqlite3.IntegrityError:
            self.send_json(HTTPStatus.CONFLICT, {"error": "이미 사용 중인 계정 이름입니다."})
        except Exception:
            self.log_error("POST 요청 처리 중 오류가 발생했습니다")
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "서버 오류가 발생했습니다."})

    def register(self) -> None:
        payload = self.read_json()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not re.fullmatch(r"[A-Za-z0-9가-힣_.-]{2,30}", username):
            raise ApiError(HTTPStatus.BAD_REQUEST, "아이디는 한글, 영문, 숫자, . _ - 조합으로 2~30자여야 합니다.")
        if len(password) < 8 or len(password) > 256:
            raise ApiError(HTTPStatus.BAD_REQUEST, "비밀번호는 8~256자로 입력해 주세요.")

        user_id = str(uuid.uuid4())
        with database() as connection:
            connection.execute(
                "INSERT INTO users(id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (user_id, username, password_digest(password), int(time.time())),
            )
            user = connection.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        self.json_response_with_session(user, self.create_session(user_id))

    def login(self) -> None:
        payload = self.read_json()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        with database() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        if user is None or not password_matches(password, user["password_hash"]):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "아이디 또는 비밀번호를 확인해 주세요.")
        self.json_response_with_session(user, self.create_session(user["id"]))

    def logout(self) -> None:
        user = self.current_user()
        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("session")
        if user is not None and morsel is not None:
            token_hash = hashlib.sha256(morsel.value.encode("utf-8")).hexdigest()
            with database() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        cleared_cookie = "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        self.send_json(HTTPStatus.OK, {"authenticated": False}, {"Set-Cookie": cleared_cookie})

    @staticmethod
    def validated_scope(value: str) -> str:
        if value not in {"mine", "community"}:
            raise ApiError(HTTPStatus.BAD_REQUEST, "보관함 구분이 올바르지 않습니다.")
        return value

    def get_folders(self, query: dict[str, list[str]]) -> None:
        scope = self.validated_scope(query.get("scope", [""])[0])
        user = self.require_user() if scope == "mine" else None
        with database() as connection:
            if scope == "mine":
                rows = connection.execute(
                    "SELECT id, parent_id, name, created_at FROM folders WHERE scope = ? AND owner_id = ? ORDER BY name COLLATE NOCASE",
                    (scope, user["id"]),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT id, parent_id, name, created_at FROM folders WHERE scope = ? ORDER BY name COLLATE NOCASE",
                    (scope,),
                ).fetchall()
        self.send_json(HTTPStatus.OK, {"folders": [dict(row) for row in rows]})

    def create_folder(self) -> None:
        user = self.require_user()
        payload = self.read_json()
        scope = self.validated_scope(str(payload.get("scope", "")))
        name = str(payload.get("name", "")).strip()
        parent_id = payload.get("parentId") or None
        if not name or len(name) > 60 or name in {".", ".."} or "/" in name or "\\" in name:
            raise ApiError(HTTPStatus.BAD_REQUEST, "폴더 이름을 1~60자로 입력해 주세요.")

        with database() as connection:
            if parent_id:
                parent = connection.execute(
                    "SELECT id FROM folders WHERE id = ? AND scope = ? AND (scope = 'community' OR owner_id = ?)",
                    (parent_id, scope, user["id"]),
                ).fetchone()
                if parent is None:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "상위 폴더를 찾을 수 없습니다.")
            duplicate = connection.execute(
                "SELECT id FROM folders WHERE scope = ? AND parent_id IS ? AND name = ?",
                (scope, parent_id, name),
            ).fetchone()
            if duplicate:
                raise ApiError(HTTPStatus.CONFLICT, "같은 이름의 폴더가 이미 있습니다.")
            folder_id = str(uuid.uuid4())
            created_at = int(time.time())
            connection.execute(
                "INSERT INTO folders(id, scope, owner_id, parent_id, name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (folder_id, scope, user["id"], parent_id, name, created_at),
            )
        self.send_json(
            HTTPStatus.CREATED,
            {"folder": {"id": folder_id, "parent_id": parent_id, "name": name, "created_at": created_at}},
        )

    def get_files(self, query: dict[str, list[str]]) -> None:
        scope = self.validated_scope(query.get("scope", [""])[0])
        folder_id = query.get("folderId", [""])[0] or None
        user = self.require_user() if scope == "mine" else None
        with database() as connection:
            if folder_id:
                folder = connection.execute(
                    "SELECT id FROM folders WHERE id = ? AND scope = ? AND (scope = 'community' OR owner_id = ?)",
                    (folder_id, scope, user["id"] if user else ""),
                ).fetchone()
                if folder is None:
                    raise ApiError(HTTPStatus.NOT_FOUND, "폴더를 찾을 수 없습니다.")

            conditions = ["files.scope = ?"]
            parameters: list[str] = [scope]
            if scope == "mine":
                conditions.append("files.owner_id = ?")
                parameters.append(user["id"])
            if folder_id:
                conditions.append("files.folder_id = ?")
                parameters.append(folder_id)
            rows = connection.execute(
                """
                SELECT files.id, files.folder_id, files.filename, files.size, files.created_at, users.username
                FROM files JOIN users ON users.id = files.owner_id
                WHERE """
                + " AND ".join(conditions)
                + " ORDER BY files.created_at DESC",
                parameters,
            ).fetchall()
        self.send_json(
            HTTPStatus.OK,
            {
                "files": [
                    {
                        "id": row["id"],
                        "folderId": row["folder_id"],
                        "name": row["filename"],
                        "size": row["size"],
                        "uploadedAt": row["created_at"],
                        "uploader": row["username"],
                    }
                    for row in rows
                ]
            },
        )

    def parse_upload(self) -> tuple[dict[str, str], list[tuple[str, bytes]]]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "파일 업로드 요청이 올바르지 않습니다.")
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + self.read_body()
        )
        if not message.is_multipart():
            raise ApiError(HTTPStatus.BAD_REQUEST, "파일 업로드 형식을 읽을 수 없습니다.")

        fields: dict[str, str] = {}
        uploads: list[tuple[str, bytes]] = []
        for part in message.iter_parts():
            field_name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename is not None:
                uploads.append((filename, payload))
            elif field_name:
                fields[field_name] = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        return fields, uploads

    def upload_files(self) -> None:
        user = self.require_user()
        fields, uploads = self.parse_upload()
        scope = self.validated_scope(fields.get("scope", ""))
        folder_id = fields.get("folderId", "")
        if not folder_id:
            raise ApiError(HTTPStatus.BAD_REQUEST, "먼저 업로드할 폴더를 선택해 주세요.")
        if not uploads:
            raise ApiError(HTTPStatus.BAD_REQUEST, "업로드할 .sav 파일을 선택해 주세요.")

        safe_uploads: list[tuple[str, bytes]] = []
        for original_name, payload in uploads:
            filename = original_name.replace("\\", "/").split("/")[-1]
            filename = re.sub(r"[\x00-\x1f\x7f]", "", filename).strip()
            if not filename.lower().endswith(".sav"):
                raise ApiError(HTTPStatus.BAD_REQUEST, ".sav 파일만 업로드할 수 있습니다.")
            if not filename or len(filename) > 180:
                raise ApiError(HTTPStatus.BAD_REQUEST, "파일 이름은 1~180자로 입력해 주세요.")
            safe_uploads.append((filename, payload))

        with database() as connection:
            folder = connection.execute(
                "SELECT id FROM folders WHERE id = ? AND scope = ? AND (scope = 'community' OR owner_id = ?)",
                (folder_id, scope, user["id"]),
            ).fetchone()
            if folder is None:
                raise ApiError(HTTPStatus.NOT_FOUND, "업로드할 폴더를 찾을 수 없습니다.")

        stored_paths: list[Path] = []
        records = []
        try:
            with database() as connection:
                for filename, payload in safe_uploads:
                    file_id = str(uuid.uuid4())
                    stored_path = UPLOAD_DIR / f"{file_id}.sav"
                    stored_path.write_bytes(payload)
                    stored_paths.append(stored_path)
                    created_at = int(time.time())
                    connection.execute(
                        "INSERT INTO files(id, scope, owner_id, folder_id, filename, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (file_id, scope, user["id"], folder_id, filename, len(payload), created_at),
                    )
                    records.append(
                        {
                            "id": file_id,
                            "folderId": folder_id,
                            "name": filename,
                            "size": len(payload),
                            "uploadedAt": created_at,
                            "uploader": user["username"],
                        }
                    )
        except Exception:
            for stored_path in stored_paths:
                stored_path.unlink(missing_ok=True)
            raise
        self.send_json(HTTPStatus.CREATED, {"files": records})

    def download_file(self, file_id: str) -> None:
        with database() as connection:
            row = connection.execute(
                "SELECT id, scope, owner_id, filename, size FROM files WHERE id = ?", (file_id,)
            ).fetchone()
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "파일을 찾을 수 없습니다.")
        if row["scope"] == "mine":
            user = self.require_user()
            if row["owner_id"] != user["id"]:
                raise ApiError(HTTPStatus.NOT_FOUND, "파일을 찾을 수 없습니다.")

        stored_path = UPLOAD_DIR / f"{row['id']}.sav"
        if not stored_path.is_file():
            raise ApiError(HTTPStatus.NOT_FOUND, "저장된 파일을 찾을 수 없습니다.")
        encoded_name = quote(row["filename"], safe="")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(row["filename"])[0] or "application/octet-stream")
        self.send_header("Content-Length", str(row["size"]))
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{encoded_name}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with stored_path.open("rb") as file_stream:
            while chunk := file_stream.read(64 * 1024):
                self.wfile.write(chunk)


def run_server(host: str, port: int) -> None:
    initialize_database()
    server = ThreadingHTTPServer((host, port), ArchiveRequestHandler)
    print(f"세이브본 아카이브 실행 중: http://{host}:{port}")
    print("중지하려면 Ctrl+C를 누르세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")
    finally:
        server.server_close()


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser(description="조별스서버 세이브본 아카이브")
    argument_parser.add_argument("--host", default="127.0.0.1", help="바인딩 주소 (기본값: 127.0.0.1)")
    argument_parser.add_argument("--port", type=int, default=8000, help="포트 번호 (기본값: 8000)")
    arguments = argument_parser.parse_args()
    run_server(arguments.host, arguments.port)