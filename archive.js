const pageScope = document.body.dataset.archiveScope;
const rootName = document.body.dataset.rootName || "보관함";
const folderList = document.getElementById("folder-list");
const fileList = document.getElementById("file-list");
const emptyFiles = document.getElementById("empty-files");
const currentFolderName = document.getElementById("current-folder-name");
const appStatus = document.getElementById("app-status");
const authDialog = document.getElementById("auth-dialog");
const authForm = document.getElementById("auth-form");
const authStatus = document.getElementById("auth-status");
const folderDialog = document.getElementById("folder-dialog");
const folderForm = document.getElementById("folder-form");
const folderStatus = document.getElementById("folder-status");
const fileInput = document.getElementById("file-input");
let currentUser = null;
let folders = [];
let activeFolderId = null;
let authMode = "login";

async function api(path, options = {}) {
    const response = await fetch(path, { credentials: "same-origin", ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(payload.error || "요청을 처리하지 못했습니다.");
    }
    return payload;
}

function setStatus(message) {
    if (appStatus) appStatus.textContent = message;
}

function setAuthStatus(message) {
    if (authStatus) authStatus.textContent = message;
}

function updateAccountControls() {
    const accountLabel = document.getElementById("account-label");
    const loginButton = document.getElementById("login-open");
    const logoutButton = document.getElementById("logout-button");
    accountLabel.hidden = !currentUser;
    accountLabel.textContent = currentUser ? currentUser.username : "";
    loginButton.hidden = Boolean(currentUser);
    logoutButton.hidden = !currentUser;

    if (pageScope === "mine") {
        document.getElementById("archive-workspace").hidden = !currentUser;
        document.getElementById("auth-required").hidden = Boolean(currentUser);
    }
}

function openAuth(mode = "login") {
    if (!authDialog) return;
    setAuthMode(mode);
    setAuthStatus("");
    authDialog.showModal();
}

function setAuthMode(mode) {
    authMode = mode;
    const isRegister = mode === "register";
    document.getElementById("auth-title").textContent = isRegister ? "회원가입" : "로그인";
    document.getElementById("auth-submit").textContent = isRegister ? "계정 만들기" : "로그인";
    document.getElementById("auth-password").autocomplete = isRegister ? "new-password" : "current-password";
    document.querySelectorAll("[data-auth-mode]").forEach((button) => {
        const active = button.dataset.authMode === mode;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-selected", String(active));
    });
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderFolders() {
    folderList.replaceChildren();
    const rootButton = document.createElement("button");
    rootButton.className = `folder-item${activeFolderId === null ? " is-active" : ""}`;
    rootButton.type = "button";
    rootButton.dataset.folderId = "";
    rootButton.setAttribute("aria-current", activeFolderId === null ? "page" : "false");
    rootButton.style.paddingInlineStart = "10px";
    const rootIcon = document.createElement("span");
    rootIcon.className = "folder-icon";
    rootIcon.textContent = "▰";
    rootIcon.setAttribute("aria-hidden", "true");
    const rootLabel = document.createElement("span");
    rootLabel.className = "folder-name";
    rootLabel.textContent = rootName;
    rootButton.append(rootIcon, rootLabel);
    folderList.append(rootButton);

    function appendChildren(parentId, depth) {
        folders
            .filter((folder) => folder.parent_id === parentId)
            .sort((first, second) => first.name.localeCompare(second.name, "ko"))
            .forEach((folder) => {
                const button = document.createElement("button");
                button.className = `folder-item${folder.id === activeFolderId ? " is-active" : ""}`;
                button.type = "button";
                button.dataset.folderId = folder.id;
                button.style.paddingInlineStart = `${28 + depth * 18}px`;
                button.setAttribute("aria-current", folder.id === activeFolderId ? "page" : "false");

                const icon = document.createElement("span");
                icon.className = "folder-icon";
                icon.setAttribute("aria-hidden", "true");
                icon.textContent = "▰";
                const name = document.createElement("span");
                name.className = "folder-name";
                name.textContent = folder.name;
                button.append(icon, name);
                folderList.append(button);
                appendChildren(folder.id, depth + 1);
            });
    }
    appendChildren(null, 0);
}

function renderFiles(files) {
    fileList.replaceChildren();
    emptyFiles.hidden = files.length > 0;
    files.forEach((file) => {
        const row = document.createElement("article");
        row.className = "file-row";
        const details = document.createElement("div");
        details.className = "file-details";
        const badge = document.createElement("span");
        badge.className = "file-badge";
        badge.textContent = "SAV";
        badge.setAttribute("aria-hidden", "true");
        const text = document.createElement("div");
        text.style.minWidth = "0";
        const name = document.createElement("h4");
        name.className = "file-name";
        name.textContent = file.name;
        const meta = document.createElement("p");
        meta.className = "file-meta";
        const date = new Date(file.uploadedAt * 1000).toLocaleDateString("ko-KR");
        meta.textContent = `${file.uploader} · ${formatSize(file.size)} · ${date}`;
        text.append(name, meta);
        details.append(badge, text);

        const actions = document.createElement("div");
        actions.className = "file-actions";
        const download = document.createElement("a");
        download.className = "file-action";
        download.href = `/api/files/${encodeURIComponent(file.id)}/download`;
        download.download = file.name;
        download.textContent = "↓";
        download.setAttribute("aria-label", `${file.name} 다운로드`);
        download.title = "다운로드";
        actions.append(download);
        row.append(details, actions);
        fileList.append(row);
    });
}

async function loadArchive() {
    if (!pageScope) return;
    if (pageScope === "mine" && !currentUser) {
        folders = [];
        activeFolderId = null;
        fileList.replaceChildren();
        return;
    }

    try {
        const folderPayload = await api(`/api/folders?scope=${pageScope}`);
        folders = folderPayload.folders;
        if (activeFolderId && !folders.some((folder) => folder.id === activeFolderId)) activeFolderId = null;
        renderFolders();
        currentFolderName.textContent = activeFolderId
            ? folders.find((folder) => folder.id === activeFolderId).name
            : rootName;

        const query = new URLSearchParams({ scope: pageScope });
        if (activeFolderId) query.set("folderId", activeFolderId);
        const filePayload = await api(`/api/files?${query}`);
        renderFiles(filePayload.files);
        if (!currentUser && pageScope === "community") setStatus("업로드와 폴더 추가는 로그인 후 이용할 수 있습니다.");
    } catch (error) {
        setStatus(error.message);
    }
}

document.getElementById("login-open").addEventListener("click", () => openAuth("login"));
document.querySelectorAll("[data-open-auth]").forEach((button) => button.addEventListener("click", () => openAuth("login")));
document.querySelectorAll("[data-auth-mode]").forEach((button) => button.addEventListener("click", () => setAuthMode(button.dataset.authMode)));
document.querySelectorAll("[data-dialog-close]").forEach((button) => {
    button.addEventListener("click", () => document.getElementById(button.dataset.dialogClose).close());
});

authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(authForm);
    const endpoint = authMode === "register" ? "/api/auth/register" : "/api/auth/login";
    try {
        currentUser = await api(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: formData.get("username"), password: formData.get("password") })
        });
        authDialog.close();
        authForm.reset();
        updateAccountControls();
        await loadArchive();
        setStatus("로그인했습니다.");
    } catch (error) {
        setAuthStatus(error.message);
    }
});

document.getElementById("logout-button").addEventListener("click", async () => {
    try {
        await api("/api/auth/logout", { method: "POST" });
        currentUser = null;
        updateAccountControls();
        await loadArchive();
        setStatus("로그아웃했습니다.");
    } catch (error) {
        setStatus(error.message);
    }
});

if (pageScope) {
    folderList.addEventListener("click", async (event) => {
        const button = event.target.closest("button[data-folder-id]");
        if (!button) return;
        activeFolderId = button.dataset.folderId || null;
        await loadArchive();
        setStatus("");
    });

    document.getElementById("add-folder-button").addEventListener("click", () => {
        if (!currentUser) {
            openAuth("login");
            return;
        }
        const parent = folders.find((folder) => folder.id === activeFolderId);
        document.getElementById("parent-folder-name").textContent = parent ? parent.name : rootName;
        document.getElementById("new-folder-name").value = "";
        folderStatus.textContent = "";
        folderDialog.showModal();
        document.getElementById("new-folder-name").focus();
    });

    folderForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const name = document.getElementById("new-folder-name").value.trim();
        try {
            const result = await api("/api/folders", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scope: pageScope, name, parentId: activeFolderId })
            });
            activeFolderId = result.folder.id;
            folderDialog.close();
            await loadArchive();
            setStatus(`'${name}' 폴더를 만들었습니다.`);
        } catch (error) {
            folderStatus.textContent = error.message;
        }
    });

    document.getElementById("upload-button").addEventListener("click", () => {
        if (!currentUser) {
            openAuth("login");
            return;
        }
        if (!activeFolderId) {
            setStatus("파일을 올리기 전에 연도별 폴더를 만들어 주세요.");
            return;
        }
        fileInput.click();
    });

    fileInput.addEventListener("change", async () => {
        const selectedFiles = Array.from(fileInput.files || []);
        const saveFiles = selectedFiles.filter((file) => file.name.toLowerCase().endsWith(".sav"));
        if (saveFiles.length === 0) {
            if (selectedFiles.length > 0) setStatus(".sav 파일만 업로드할 수 있습니다.");
            fileInput.value = "";
            return;
        }
        const formData = new FormData();
        formData.append("scope", pageScope);
        formData.append("folderId", activeFolderId);
        saveFiles.forEach((file) => formData.append("files", file));
        try {
            const result = await api("/api/files", { method: "POST", body: formData });
            await loadArchive();
            setStatus(`${result.files.length}개 파일을 업로드했습니다.`);
        } catch (error) {
            setStatus(error.message);
        } finally {
            fileInput.value = "";
        }
    });
}

async function initializePage() {
    try {
        const session = await api("/api/me");
        currentUser = session.authenticated ? session : null;
    } catch {
        currentUser = null;
    }
    updateAccountControls();
    await loadArchive();
}

initializePage();