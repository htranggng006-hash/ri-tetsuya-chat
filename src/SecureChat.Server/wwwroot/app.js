// ==========================================================================
// SECURE CHAT - FACEBOOK MESSENGER INTERFACE CONTROLLER
// Features: ElGamal-AES Hybrid E2EE, Digital Signatures, Key Management,
// Friends System, Message Recall (Unsend), Custom Avatars, Light/Dark Theme
// ==========================================================================

let hubConnection = null;
let currentUser = null; // KeyBundleResponse with { userId, avatarUrl, friends, ... }
let contacts = new Map(); // userId -> UserPublicKeyAnnouncement
let currentRecipientId = null;
let messages = []; // Array of chat message records
let currentContactTab = "friends"; // 'friends' or 'all'

// Preset avatar styles
const AVATAR_PRESETS = [
    { id: "ritetsuya", name: "Mèo Ri Tetsuya", icon: "logo.png", isImg: true, bg: "rgba(255, 255, 255, 0.08)" },
    { id: "p1", name: "Cyber Ninja", icon: "🥷", bg: "linear-gradient(135deg, #11998e, #38ef7d)" },
    { id: "p2", name: "Hacker Neon", icon: "👨‍💻", bg: "linear-gradient(135deg, #8e2de2, #4a00e0)" },
    { id: "p3", name: "AI Robot", icon: "🤖", bg: "linear-gradient(135deg, #0084ff, #00c6ff)" },
    { id: "p4", name: "Cyber Cat", icon: "🐱", bg: "linear-gradient(135deg, #f857a6, #ff5858)" },
    { id: "p5", name: "Astronaut", icon: "🚀", bg: "linear-gradient(135deg, #fc4a1a, #f7b733)" },
    { id: "p6", name: "Super Hero", icon: "🦸", bg: "linear-gradient(135deg, #ff0844, #ffb199)" },
    { id: "p7", name: "Galaxy Alien", icon: "👾", bg: "linear-gradient(135deg, #00b4db, #0083b0)" },
    { id: "p8", name: "Security Shield", icon: "🛡️", bg: "linear-gradient(135deg, #43e97b, #38f9d7)" }
];

// Color palette for contact avatars fallback
const AVATAR_GRADIENTS = [
    "linear-gradient(135deg, #0084ff, #00c6ff)",
    "linear-gradient(135deg, #f857a6, #ff5858)",
    "linear-gradient(135deg, #11998e, #38ef7d)",
    "linear-gradient(135deg, #fc4a1a, #f7b733)",
    "linear-gradient(135deg, #8e2de2, #4a00e0)",
    "linear-gradient(135deg, #ff0844, #ffb199)"
];

function getAvatarColor(name) {
    if (!name) return AVATAR_GRADIENTS[0];
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash += name.charCodeAt(i);
    return AVATAR_GRADIENTS[Math.abs(hash) % AVATAR_GRADIENTS.length];
}

// Quick fill for login/register demo
function quickFillReg(name) {
    document.getElementById("reg-username").value = name;
}
function quickFillLogin(name) {
    document.getElementById("login-username").value = name;
}

window.switchAuthTab = function(tab) {
    const tabReg = document.getElementById("tab-btn-register");
    const tabLog = document.getElementById("tab-btn-login");
    const formReg = document.getElementById("form-register");
    const formLog = document.getElementById("form-login");
    const importSec = document.getElementById("import-section");

    importSec.style.display = "none";

    if (tab === "register") {
        tabReg.classList.add("active");
        tabLog.classList.remove("active");
        formReg.style.display = "block";
        formLog.style.display = "none";
    } else {
        tabLog.classList.add("active");
        tabReg.classList.remove("active");
        formLog.style.display = "block";
        formReg.style.display = "none";
    }
};

// ==========================================================================
// SESSION PERSISTENCE (REMEMBER ME / AUTO-LOGIN)
// ==========================================================================
const SESSION_KEY = "ritetsuya_chat_session";

function saveSession(username, password, remember) {
    try {
        const sessionData = JSON.stringify({ username, password, remember });
        if (remember) {
            localStorage.setItem(SESSION_KEY, sessionData);
            sessionStorage.removeItem(SESSION_KEY);
        } else {
            sessionStorage.setItem(SESSION_KEY, sessionData);
            localStorage.removeItem(SESSION_KEY);
        }
    } catch (e) {
        console.warn("Lỗi lưu session:", e);
    }
}

function clearSession() {
    try {
        localStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_KEY);
    } catch (e) {
        console.warn("Lỗi xóa session:", e);
    }
}

function getStoredSession() {
    try {
        const s = localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY);
        return s ? JSON.parse(s) : null;
    } catch (e) {
        return null;
    }
}

async function checkAutoLogin() {
    const session = getStoredSession();
    if (!session || !session.username || !session.password) {
        return false;
    }

    const uField = document.getElementById("login-username");
    const pField = document.getElementById("login-password");
    if (uField) uField.value = session.username;
    if (pField) pField.value = session.password;
    const rField = document.getElementById("login-remember-me");
    if (rField) rField.checked = !!session.remember;

    showLoading(true, `Đang khôi phục phiên đăng nhập cho '${session.username}'...`);
    try {
        const resp = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: session.username, password: session.password })
        });

        if (!resp.ok) {
            clearSession();
            showLoading(false);
            return false;
        }

        const keyBundle = await resp.json();
        currentUser = keyBundle;
        currentUser.passphrase = session.password;

        await connectSignalR(keyBundle);
        finishLogin();
        return true;
    } catch (err) {
        console.warn("Auto-login failed:", err);
        showLoading(false);
        return false;
    } finally {
        showLoading(false);
    }
}

// ==========================================================================
// MOBILE & RESPONSIVE UI HELPERS
// ==========================================================================

window.backToContactList = function() {
    const workspace = document.getElementById("main-workspace");
    if (workspace) {
        workspace.classList.remove("mobile-chat-open");
    }
    window.toggleInfoPanel(false);
};

window.toggleAttackBar = function(force) {
    const bar = document.getElementById("attack-toolbar");
    if (!bar) return;
    const isHidden = bar.style.display === "none" || !bar.style.display;
    const show = force !== undefined ? force : isHidden;
    bar.style.display = show ? "flex" : "none";
};

window.toggleInfoPanel = function(force) {
    const panel = document.getElementById("msg-info-panel");
    const backdrop = document.getElementById("info-panel-backdrop");
    if (!panel) return;

    const isMobile = window.innerWidth <= 1024;
    if (isMobile) {
        const willOpen = force !== undefined ? force : !panel.classList.contains("open");
        panel.classList.toggle("open", willOpen);
        if (backdrop) backdrop.classList.toggle("active", willOpen);
    } else {
        const willCollapse = force !== undefined ? !force : !panel.classList.contains("collapsed");
        panel.classList.toggle("collapsed", willCollapse);
    }
// ==========================================================================
// EMAIL OTP VERIFICATION
// ==========================================================================
let otpCooldownInterval = null;
let currentDevOtp = null;

window.requestEmailOtp = async function() {
    const email = document.getElementById("reg-email")?.value.trim();
    const username = document.getElementById("reg-username")?.value.trim() || "Người dùng";

    if (!email) {
        alert("Vui lòng nhập địa chỉ Email trước khi yêu cầu gửi mã OTP!");
        document.getElementById("reg-email")?.focus();
        return;
    }

    if (!email.includes("@") || !email.includes(".")) {
        alert("Địa chỉ email không hợp lệ! Vui lòng nhập đúng định dạng (ví dụ: name@gmail.com).");
        document.getElementById("reg-email")?.focus();
        return;
    }

    const btn = document.getElementById("btn-send-otp");
    const btnText = document.getElementById("btn-send-otp-text");
    btn.disabled = true;
    if (btnText) btnText.innerText = "Đang gửi...";

    try {
        const resp = await fetch("/api/auth/send-email-otp", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email, username: username })
        });

        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
            throw new Error(data.error || "Không thể gửi OTP.");
        }

        currentDevOtp = data.devOtp;

        // Show status toast
        showOtpToast(data.message, data.devOtp, !data.realEmailSent);

        const hintEl = document.getElementById("otp-hint");
        const hintText = document.getElementById("otp-hint-text");
        if (hintEl) hintEl.style.display = "flex";
        if (hintText) {
            hintText.innerText = data.realEmailSent
                ? `Đã gửi mã OTP đến ${email}. Hãy kiểm tra hộp thư đến hoặc Spam!`
                : `Đã tạo mã OTP mô phỏng (Chưa cấu hình API Key Email): ${data.devOtp}`;
        }

        const otpInput = document.getElementById("reg-otp");
        if (otpInput) otpInput.focus();

        // 60-second cooldown
        let remaining = 60;
        if (btnText) btnText.innerText = `Gửi lại (${remaining}s)`;
        if (otpCooldownInterval) clearInterval(otpCooldownInterval);
        otpCooldownInterval = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(otpCooldownInterval);
                btn.disabled = false;
                if (btnText) btnText.innerText = "Gửi OTP qua Email";
            } else {
                if (btnText) btnText.innerText = `Gửi lại (${remaining}s)`;
            }
        }, 1000);

    } catch (err) {
        alert("Lỗi gửi OTP: " + err.message);
        btn.disabled = false;
        if (btnText) btnText.innerText = "Gửi OTP qua Email";
    }
};

window.showOtpToast = function(statusMsg, devCode, isSimulated) {
    const toast = document.getElementById("otp-toast");
    const statusEl = document.getElementById("otp-toast-status-msg");
    const devWrap = document.getElementById("otp-toast-dev-wrap");
    const codeEl = document.getElementById("toast-otp-code");

    if (!toast) return;
    if (statusEl) statusEl.innerText = statusMsg;

    if (isSimulated && devCode) {
        if (devWrap) devWrap.style.display = "block";
        if (codeEl) codeEl.innerText = devCode;
    } else {
        if (devWrap) devWrap.style.display = "none";
    }

    toast.style.display = "block";
};

window.closeOtpToast = function() {
    const toast = document.getElementById("otp-toast");
    if (toast) toast.style.display = "none";
};

window.autoFillOtp = function() {
    if (currentDevOtp) {
        const otpInput = document.getElementById("reg-otp");
        if (otpInput) {
            otpInput.value = currentDevOtp;
            closeOtpToast();
        }
    }
};

document.addEventListener("DOMContentLoaded", async () => {
    initTheme();
    setupAuthHandlers();
    setupChatComposer();
    setupRightPanel();

    // Check MongoDB persistence service status
    checkMongoStatus();
    setInterval(checkMongoStatus, 15000);

    // Close any floating action menus on document click
    document.addEventListener("click", () => {
        document.querySelectorAll(".msg-action-menu").forEach(m => m.style.display = "none");
    });

    // Check Auto-login on load (Remember Me)
    await checkAutoLogin();
});

// ==========================================================================
// 1. LIGHT / DARK THEME TOGGLE
// ==========================================================================

function initTheme() {
    const saved = localStorage.getItem("messenger_theme") || "dark";
    if (saved === "light") {
        document.body.classList.remove("messenger-dark");
        document.body.classList.add("messenger-light");
        const icon = document.getElementById("theme-icon");
        if (icon) icon.className = "fas fa-sun";
    }
}

window.toggleTheme = function() {
    const isLight = document.body.classList.contains("messenger-light");
    if (isLight) {
        document.body.classList.remove("messenger-light");
        document.body.classList.add("messenger-dark");
        const icon = document.getElementById("theme-icon");
        if (icon) icon.className = "fas fa-moon";
        localStorage.setItem("messenger_theme", "dark");
    } else {
        document.body.classList.remove("messenger-dark");
        document.body.classList.add("messenger-light");
        const icon = document.getElementById("theme-icon");
        if (icon) icon.className = "fas fa-sun";
        localStorage.setItem("messenger_theme", "light");
    }
};

// ==========================================================================
// 2. AUTHENTICATION & KEY INITIALIZATION
// ==========================================================================

function setupAuthHandlers() {
    const btnRegister = document.getElementById("btn-submit-register");
    const btnLogin = document.getElementById("btn-submit-login");
    const btnShowImport = document.getElementById("btn-show-import");
    const btnImport = document.getElementById("btn-import-keystore");
    const importSection = document.getElementById("import-section");
    const btnLogout = document.getElementById("btn-logout");

    btnShowImport.addEventListener("click", () => {
        importSection.style.display = importSection.style.display === "none" ? "block" : "none";
    });

    // 1. REGISTER
    btnRegister.addEventListener("click", async () => {
        const username = document.getElementById("reg-username").value.trim();
        const email = document.getElementById("reg-email").value.trim();
        const password = document.getElementById("reg-password").value;
        const confirmPassword = document.getElementById("reg-confirm-password").value;
        const otp = document.getElementById("reg-otp")?.value.trim();
        const group = "rfc2048";

        if (!username) { alert("Vui lòng nhập tên tài khoản!"); return; }
        if (!email) { 
            alert("Vui lòng nhập địa chỉ Email nhận mã OTP!"); 
            document.getElementById("reg-email")?.focus();
            return; 
        }
        if (!password || password.length < 6) { alert("Mật khẩu phải từ 6 ký tự trở lên!"); return; }
        if (password !== confirmPassword) { alert("Xác nhận mật khẩu không khớp!"); return; }
        if (!otp) {
            alert("Vui lòng bấm 'Gửi OTP qua Email' và nhập mã xác nhận 6 chữ số!");
            document.getElementById("reg-otp")?.focus();
            return;
        }

        showLoading(true, "Đang xác thực OTP, sinh cặp khóa ElGamal 2048-bit và mã hóa Keystore PBKDF2...");
        try {
            const resp = await fetch("/api/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    username: username, 
                    email: email, 
                    password: password, 
                    otp: otp, 
                    groupName: group 
                })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.error || "Đăng ký thất bại.");
            }

            const keyBundle = await resp.json();
            currentUser = keyBundle;
            currentUser.passphrase = password;

            const rememberMe = document.getElementById("reg-remember-me")?.checked ?? true;
            saveSession(username, password, rememberMe);

            await connectSignalR(keyBundle);
            finishLogin();
        } catch (err) {
            alert("Lỗi đăng ký: " + err.message);
        } finally {
            showLoading(false);
        }
    });

    // 2. LOGIN
    btnLogin.addEventListener("click", async () => {
        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value;

        if (!username) { alert("Vui lòng nhập tên tài khoản!"); return; }
        if (!password) { alert("Vui lòng nhập mật khẩu!"); return; }

        showLoading(true, "Đang xác thực PBKDF2 và mở khóa Keystore...");
        try {
            const resp = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: username, password: password })
            });

            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.error || "Đăng nhập thất bại.");
            }

            const keyBundle = await resp.json();
            currentUser = keyBundle;
            currentUser.passphrase = password;

            const rememberMe = document.getElementById("login-remember-me")?.checked ?? true;
            saveSession(username, password, rememberMe);

            await connectSignalR(keyBundle);
            finishLogin();
        } catch (err) {
            alert("Lỗi đăng nhập: " + err.message);
        } finally {
            showLoading(false);
        }
    });

    // 3. IMPORT KEYSTORE FILE
    btnImport.addEventListener("click", async () => {
        const fileInput = document.getElementById("keystore-file-input");
        const password = document.getElementById("login-password").value;

        if (!fileInput.files.length) { alert("Vui lòng chọn tệp Keystore JSON!"); return; }
        if (!password) { alert("Vui lòng nhập mật khẩu mở khóa Keystore ở ô Mật khẩu!"); return; }

        const file = fileInput.files[0];
        const text = await file.text();

        showLoading(true, "Đang giải mã và mở khóa tệp Keystore...");
        try {
            const resp = await fetch("/api/crypto/import-keystore", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ keystoreJson: text, passphrase: password })
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.error || "Mật khẩu sai hoặc tệp hỏng.");
            }
            const keyBundle = await resp.json();
            currentUser = keyBundle;
            currentUser.passphrase = password;

            saveSession(keyBundle.userId, password, true);

            await connectSignalR(keyBundle);
            finishLogin();
        } catch (err) {
            alert("Lỗi khôi phục Keystore: " + err.message);
        } finally {
            showLoading(false);
        }
    });

    btnLogout.addEventListener("click", () => {
        clearSession();
        if (hubConnection) hubConnection.stop();
        location.reload();
    });
}

function showLoading(show, text) {
    document.getElementById("auth-loading").style.display = show ? "block" : "none";
    if (text) document.getElementById("loading-text").innerText = text;
}

function finishLogin() {
    document.getElementById("auth-overlay").style.display = "none";
    document.getElementById("main-workspace").style.display = "flex";

    document.getElementById("bar-username").innerText = currentUser.userId;
    updateMyAvatarDisplay();

    document.getElementById("my-fingerprint-display").innerText = currentUser.combinedFingerprint;

    if (!currentUser.friends) currentUser.friends = [];
    updateFriendCounts();
    renderKeyManagementDetails();
}

// ==========================================================================
// 3. SIGNALR REAL-TIME RELAY
// ==========================================================================

async function connectSignalR(bundle) {
    hubConnection = new signalR.HubConnectionBuilder()
        .withUrl("/chathub")
        .withAutomaticReconnect([0, 1000, 2000, 5000, 10000])
        .build();

    hubConnection.on("DirectorySync", (directoryList) => {
        contacts.clear();
        directoryList.forEach(user => {
            if (user.userId !== currentUser.userId) {
                contacts.set(user.userId, user);
            }
        });
        updateFriendCounts();
        renderContactList();
    });

    hubConnection.on("UserJoined", (user) => {
        if (user.userId !== currentUser.userId) {
            contacts.set(user.userId, user);
            updateFriendCounts();
            renderContactList();
        }
    });

    hubConnection.on("UserLeft", (userId) => {
        contacts.delete(userId);
        updateFriendCounts();
        renderContactList();
        if (currentRecipientId === userId) {
            updateRecipientHeader();
        }
    });

    hubConnection.on("KeysUpdated", (user) => {
        if (contacts.has(user.userId)) {
            contacts.set(user.userId, user);
            renderContactList();
            if (currentRecipientId === user.userId) {
                updateRecipientHeader();
            }
            alert(`Thông báo: Người dùng ${user.userId} vừa cập nhật lại bộ khóa mới!\nDấu vân tay mới: ${user.combinedFingerprint}`);
        }
    });

    hubConnection.on("ReceiveEnvelope", async (envelope) => {
        await handleIncomingEnvelope(envelope);
    });

    hubConnection.on("MessageSentAck", (envelope) => {
        console.log("Server đã chuyển tiếp phong bì mật mã:", envelope.messageId);
    });

    // Realtime Avatar Update Listener
    hubConnection.on("UserAvatarUpdated", (userId, avatarUrl) => {
        if (contacts.has(userId)) {
            const c = contacts.get(userId);
            c.avatarUrl = avatarUrl;
            renderContactList();
            if (currentRecipientId === userId) {
                updateRecipientHeader();
            }
        }
        if (currentUser && currentUser.userId === userId) {
            currentUser.avatarUrl = avatarUrl;
            updateMyAvatarDisplay();
        }
    });

    // Realtime Friends Update Listener
    hubConnection.on("FriendsUpdated", (friendsList) => {
        if (currentUser) {
            currentUser.friends = friendsList || [];
            updateFriendCounts();
            renderContactList();
            updateRecipientHeader();
        }
    });

    hubConnection.onreconnecting((err) => {
        console.warn("SignalR đang tự động kết nối lại...", err);
    });

    hubConnection.onreconnected(async (connectionId) => {
        console.log("SignalR đã kết nối lại thành công:", connectionId);
        if (currentUser) {
            await announcePublicKeys(currentUser);
        }
    });

    await hubConnection.start();
    await announcePublicKeys(bundle);
}

async function announcePublicKeys(bundle) {
    if (!hubConnection || hubConnection.state !== signalR.HubConnectionState.Connected) return;
    const announcement = {
        userId: bundle.userId,
        keyId: bundle.keyId,
        createdAt: bundle.createdAt,
        isActive: bundle.isActive,
        encryptionPublicKey: bundle.encryptionPublicKey,
        signingPublicKey: bundle.signingPublicKey,
        encryptionFingerprint: bundle.encryptionFingerprint,
        signingFingerprint: bundle.signingFingerprint,
        combinedFingerprint: bundle.combinedFingerprint,
        avatarUrl: bundle.avatarUrl || ""
    };
    await hubConnection.invoke("Register", announcement);
}

// ==========================================================================
// 4. AVATAR DISPLAY & SELECTION
// ==========================================================================

function renderAvatarIntoElement(el, userId, avatarUrl) {
    if (!el) return;
    const initial = (userId || "?").charAt(0).toUpperCase();

    if (avatarUrl) {
        if (avatarUrl.startsWith("preset:")) {
            const pId = avatarUrl.replace("preset:", "");
            const p = AVATAR_PRESETS.find(x => x.id === pId);
            if (p) {
                el.style.background = p.bg;
                if (p.isImg) {
                    el.innerHTML = `<img src="${p.icon}" class="avatar-img" alt="${userId}" />`;
                } else {
                    el.innerHTML = `<span style="font-size: 1.25rem;">${p.icon}</span>`;
                }
                return;
            }
        } else if (avatarUrl.startsWith("data:") || avatarUrl.startsWith("http")) {
            el.style.background = "transparent";
            el.innerHTML = `<img src="${avatarUrl}" class="avatar-img" alt="${userId}" />`;
            return;
        }
    }

    el.style.background = getAvatarColor(userId);
    el.innerText = initial;
}

function updateMyAvatarDisplay() {
    const el = document.getElementById("my-avatar-initials");
    if (!el) return;
    const initial = (currentUser.userId || "A").charAt(0).toUpperCase();

    el.style.background = getAvatarColor(currentUser.userId);
    el.innerHTML = `<span id="my-avatar-letter">${initial}</span>`;
}

// ==========================================================================
// 5. FRIENDS SYSTEM
// ==========================================================================

window.switchContactFilter = function(tab) {
    currentContactTab = tab;
    document.getElementById("tab-contacts-friends").classList.toggle("active", tab === "friends");
    document.getElementById("tab-contacts-all").classList.toggle("active", tab === "all");
    const title = document.getElementById("conv-header-title");
    if (title) title.innerText = tab === "friends" ? "Bạn bè của bạn" : "Tất cả người dùng trên hệ thống";
    renderContactList();
};

function updateFriendCounts() {
    const friendCountEl = document.getElementById("friend-count");
    const allCountEl = document.getElementById("all-count");
    if (friendCountEl) friendCountEl.innerText = (currentUser?.friends || []).length;
    if (allCountEl) allCountEl.innerText = contacts.size;
}

window.openAddFriendModal = function() {
    document.getElementById("add-friend-modal").style.display = "flex";
    document.getElementById("add-friend-input").value = "";
    document.getElementById("add-friend-input").focus();
};

window.closeAddFriendModal = function() {
    document.getElementById("add-friend-modal").style.display = "none";
};

window.submitAddFriend = async function() {
    const friendName = document.getElementById("add-friend-input").value.trim();
    if (!friendName) {
        alert("Vui lòng nhập tên tài khoản muốn kết bạn!");
        return;
    }
    if (friendName.toLowerCase() === currentUser.userId.toLowerCase()) {
        alert("Bạn không thể tự kết bạn với chính mình!");
        return;
    }
    await addFriend(friendName);
    closeAddFriendModal();
};

window.addFriend = async function(friendName) {
    try {
        const resp = await fetch("/api/friends/add", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUser.userId, friendUsername: friendName })
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.error || "Thêm bạn thất bại.");
        }
        const data = await resp.json();
        currentUser.friends = data.friends;
        updateFriendCounts();
        renderContactList();
        updateRecipientHeader();
        alert(`Đã kết bạn thành công với ${friendName}!`);
    } catch (err) {
        alert("Lỗi kết bạn: " + err.message);
    }
};

window.removeFriend = async function(friendName) {
    try {
        const resp = await fetch("/api/friends/remove", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUser.userId, friendUsername: friendName })
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.error || "Hủy kết bạn thất bại.");
        }
        const data = await resp.json();
        currentUser.friends = data.friends;
        updateFriendCounts();
        renderContactList();
        updateRecipientHeader();
        alert(`Đã xóa ${friendName} khỏi danh sách bạn bè.`);
    } catch (err) {
        alert("Lỗi xóa bạn: " + err.message);
    }
};

window.toggleCurrentFriendship = async function() {
    if (!currentRecipientId) return;
    const isFriend = currentUser.friends && currentUser.friends.some(f => f.toLowerCase() === currentRecipientId.toLowerCase());
    if (isFriend) {
        if (confirm(`Bạn có chắc chắn muốn XÓA BẠN BÈ với '${currentRecipientId}' không?`)) {
            await removeFriend(currentRecipientId);
        }
    } else {
        await addFriend(currentRecipientId);
    }
};

// ==========================================================================
// 6. MESSENGER CONVERSATIONS & CONTACTS UI
// ==========================================================================

function renderContactList() {
    const listEl = document.getElementById("contact-list");
    const storiesEl = document.getElementById("stories-row");
    listEl.innerHTML = "";
    storiesEl.innerHTML = "";

    const myFriends = currentUser?.friends || [];
    let displayedContacts = [];

    contacts.forEach((contact, userId) => {
        const isFriend = myFriends.some(f => f.toLowerCase() === userId.toLowerCase());
        if (currentContactTab === "friends") {
            if (isFriend) displayedContacts.push({ contact, userId, isFriend });
        } else {
            displayedContacts.push({ contact, userId, isFriend });
        }

        // Stories circle for all active users
        const storyItem = document.createElement("div");
        storyItem.className = "story-circle-item";
        storyItem.innerHTML = `
            <div class="avatar avatar-md" id="story-avatar-${userId}" style="position: relative;">
                <span class="avatar-badge-online"></span>
            </div>
            <span>${userId}</span>
        `;
        storiesEl.appendChild(storyItem);
        const storyAv = document.getElementById(`story-avatar-${userId}`);
        renderAvatarIntoElement(storyAv, userId, contact.avatarUrl);
        storyItem.addEventListener("click", () => selectRecipient(userId));
    });

    if (displayedContacts.length === 0) {
        if (currentContactTab === "friends") {
            listEl.innerHTML = `
                <div style="padding: 24px 16px; text-align: center; color: var(--msg-text-muted); font-size: 0.85rem;">
                    <i class="fas fa-user-friends" style="font-size: 2.2rem; margin-bottom: 8px; color: var(--msg-blue); display: block;"></i>
                    Chưa có bạn bè nào.<br>
                    Bấm nút <b>[+]</b> hoặc chuyển sang tab <b>'Tất cả'</b> để kết bạn!
                </div>
            `;
        } else {
            listEl.innerHTML = `
                <div style="padding: 24px 16px; text-align: center; color: var(--msg-text-muted); font-size: 0.85rem;">
                    Chưa có người dùng nào khác online trên hệ thống.
                </div>
            `;
        }
        return;
    }

    displayedContacts.forEach(({ contact, userId, isFriend }) => {
        const lastMsg = getLastMessageWith(userId);
        const lastPreview = lastMsg ? (lastMsg.isMe ? "Bạn: " : "") + (lastMsg.isRecalled ? "Tin nhắn đã thu hồi" : (lastMsg.isError ? "🚨 Lỗi xác thực" : lastMsg.plaintext)) : "Bắt đầu cuộc trò chuyện E2EE...";
        const lastTime = lastMsg ? new Date(lastMsg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "";

        const item = document.createElement("div");
        item.className = "conversation-item" + (currentRecipientId === userId ? " active" : "");
        item.innerHTML = `
            <div class="conv-avatar-wrap">
                <div class="avatar avatar-md" id="conv-avatar-${userId}"></div>
                <span class="avatar-badge-online"></span>
            </div>
            <div class="conv-meta">
                <div class="conv-name-row">
                    <span class="conv-name">${userId} ${isFriend ? '<i class="fas fa-check-circle friend-badge" title="Bạn bè"></i>' : ''}</span>
                    <span class="conv-time">${lastTime}</span>
                </div>
                <div class="conv-preview">${escapeHtml(lastPreview)}</div>
            </div>
            ${!isFriend && currentContactTab === "all" ? `
            <button class="btn-add-friend-sm" onclick="event.stopPropagation(); addFriend('${userId}')" title="Thêm vào danh sách bạn bè">
                <i class="fas fa-user-plus"></i> Kết bạn
            </button>
            ` : ''}
        `;

        listEl.appendChild(item);
        const convAv = document.getElementById(`conv-avatar-${userId}`);
        renderAvatarIntoElement(convAv, userId, contact.avatarUrl);
        item.addEventListener("click", () => selectRecipient(userId));
    });
}

function getLastMessageWith(userId) {
    for (let i = messages.length - 1; i >= 0; i--) {
        const m = messages[i];
        if ((m.senderId === currentUser.userId && m.recipientId === userId) ||
            (m.senderId === userId && m.recipientId === currentUser.userId)) {
            return m;
        }
    }
    return null;
}

function selectRecipient(userId) {
    currentRecipientId = userId;
    renderContactList();
    updateRecipientHeader();
    renderChatHistory();
    // Non-blocking background history load
    loadChatHistoryFromMongo(userId);

    // Mobile view switch: open chat thread
    const workspace = document.getElementById("main-workspace");
    if (workspace) {
        workspace.classList.add("mobile-chat-open");
    }
}

function updateRecipientHeader() {
    const nameEl = document.getElementById("current-recipient-name");
    const avatarEl = document.getElementById("active-recipient-avatar");
    const btnVerify = document.getElementById("btn-verify-contact");
    const infoAvatar = document.getElementById("info-panel-avatar");
    const infoName = document.getElementById("info-panel-name");
    const btnFriendToggle = document.getElementById("btn-friend-toggle");

    if (!currentRecipientId || !contacts.has(currentRecipientId)) {
        nameEl.innerText = "Chọn một đoạn chat";
        avatarEl.innerText = "?";
        avatarEl.style.background = "#3e4042";
        btnVerify.style.display = "none";
        infoAvatar.innerText = "?";
        infoName.innerText = "Chọn đoạn chat";
        if (btnFriendToggle) btnFriendToggle.style.display = "none";
        return;
    }

    const contact = contacts.get(currentRecipientId);
    nameEl.innerText = contact.userId;
    renderAvatarIntoElement(avatarEl, contact.userId, contact.avatarUrl);
    btnVerify.style.display = "inline-flex";

    renderAvatarIntoElement(infoAvatar, contact.userId, contact.avatarUrl);
    infoName.innerText = contact.userId;

    document.getElementById("info-contact-fp").innerText = contact.combinedFingerprint;
    document.getElementById("info-contact-y-enc").innerText = contact.encryptionPublicKey.y_Hex.substring(0, 36) + "...";
    document.getElementById("info-contact-y-sig").innerText = contact.signingPublicKey.y_Hex.substring(0, 36) + "...";

    // Update Friend Toggle Button in Info Panel
    if (btnFriendToggle) {
        btnFriendToggle.style.display = "block";
        const isFriend = currentUser.friends && currentUser.friends.some(f => f.toLowerCase() === currentRecipientId.toLowerCase());
        if (isFriend) {
            btnFriendToggle.className = "msg-btn btn-danger";
            btnFriendToggle.innerHTML = '<i class="fas fa-user-minus"></i> Hủy kết bạn (Xóa bạn)';
        } else {
            btnFriendToggle.className = "msg-btn msg-btn-primary";
            btnFriendToggle.innerHTML = '<i class="fas fa-user-plus"></i> Thêm vào danh sách bạn bè';
        }
    }
}

window.filterContacts = function() {
    const q = document.getElementById("contact-search-input").value.toLowerCase();
    const items = document.querySelectorAll(".conversation-item");
    items.forEach(el => {
        const name = el.querySelector(".conv-name").innerText.toLowerCase();
        el.style.display = name.includes(q) ? "flex" : "none";
    });
};

// ==========================================================================
// 7. CHAT COMPOSER & MESSAGING
// ==========================================================================

function setupChatComposer() {
    const btnSend = document.getElementById("btn-send-message");
    const msgInput = document.getElementById("message-input");
    const btnVerify = document.getElementById("btn-verify-contact");
    const infoVerifyBtn = document.getElementById("info-verify-btn");

    msgInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") btnSend.click();
    });

    btnSend.addEventListener("click", () => sendMessage());

    btnVerify.addEventListener("click", openVerifyModal);
    infoVerifyBtn.addEventListener("click", openVerifyModal);
}

window.sendQuickEmoji = function(emoji) {
    const input = document.getElementById("message-input");
    input.value = emoji;
    sendMessage();
};

async function sendMessage() {
    const input = document.getElementById("message-input");
    const text = input.value.trim();
    if (!text) return;

    if (!currentRecipientId || !contacts.has(currentRecipientId)) {
        alert("Vui lòng chọn một người bạn từ danh bạ bên trái để bắt đầu chat!");
        return;
    }

    const recipient = contacts.get(currentRecipientId);
    const mode = document.querySelector('input[name="send-mode"]:checked').value;

    // 1. OPTIMISTIC UI: Clear input immediately & display bubble in chat thread (0ms delay)
    input.value = "";
    input.focus();

    const tempId = "msg-" + Date.now() + "-" + Math.random().toString(36).substring(2, 7);
    const localMsg = {
        messageId: tempId,
        isMe: true,
        senderId: currentUser.userId,
        recipientId: recipient.userId,
        plaintext: text,
        envelope: null,
        inspection: null,
        isTampered: false,
        tamperType: "",
        isSending: true,
        timestamp: new Date()
    };

    messages.push(localMsg);
    renderChatHistory();
    renderContactList();

    // 2. SEAL & DISPATCH ASYNCHRONOUSLY
    try {
        let sealResp;
        try {
            sealResp = await fetch("/api/crypto/seal-message", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    senderId: currentUser.userId,
                    recipientId: recipient.userId,
                    senderEncPublicKey: currentUser.encryptionPublicKey,
                    senderEncPrivateKey: currentUser.encryptionPrivateKey,
                    senderSigPublicKey: currentUser.signingPublicKey,
                    senderSigPrivateKey: currentUser.signingPrivateKey,
                    recipientEncPublicKey: recipient.encryptionPublicKey,
                    senderSigFingerprint: currentUser.signingFingerprint,
                    senderEncFingerprint: currentUser.encryptionFingerprint,
                    recipientEncFingerprint: recipient.encryptionFingerprint,
                    plaintext: text
                })
            });
        } catch (fetchErr) {
            console.error("Lỗi fetch /api/crypto/seal-message:", fetchErr);
            throw new Error(`Mất kết nối máy chủ (${fetchErr.message}).`);
        }

        if (!sealResp.ok) {
            const errData = await sealResp.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${sealResp.status}: Lỗi niêm phong phong bì mật mã.`);
        }

        const outcome = await sealResp.json();
        const envelope = outcome.envelope;
        const inspection = outcome.inspection;

        // Apply attacks if chosen
        let isTampered = false;
        let tamperType = "";

        if (mode === "tamper-cipher") {
            isTampered = true;
            tamperType = "Ciphertext";
            envelope.ciphertextBase64 = btoa("NoiDungBiSuaDoiTrenDuongTruyen!");
        } else if (mode === "tamper-sig") {
            isTampered = true;
            tamperType = "Chữ ký (r,s)";
            envelope.signature.rHex = "DEADBEEF" + envelope.signature.rHex.substring(8);
        } else if (mode === "tamper-sender") {
            isTampered = true;
            tamperType = "Người gửi (AAD)";
            envelope.senderId = "AttackerEve";
        }

        // 3. Ensure SignalR connection is active and transmit envelope
        if (!hubConnection || hubConnection.state !== signalR.HubConnectionState.Connected) {
            console.warn("SignalR chưa sẵn sàng, đang kết nối lại...");
            try {
                if (hubConnection) await hubConnection.start();
                if (currentUser) await announcePublicKeys(currentUser);
            } catch (reconErr) {
                console.error("Không thể kết nối lại SignalR:", reconErr);
                throw new Error("Mất kết nối truyền tin thời gian thực (SignalR).");
            }
        }

        // Send over WebSocket without blocking
        await hubConnection.send("SendEnvelope", envelope);

        // 4. Update local message state to confirmed sent
        localMsg.messageId = envelope.messageId;
        localMsg.envelope = envelope;
        localMsg.inspection = inspection;
        localMsg.isTampered = isTampered;
        localMsg.tamperType = tamperType;
        localMsg.isSending = false;

        renderChatHistory();
        renderContactList();
    } catch (err) {
        localMsg.isSending = false;
        localMsg.isError = true;
        localMsg.errorMessage = "Gửi thất bại: " + err.message;
        renderChatHistory();
        console.error("Lỗi gửi tin nhắn:", err);
    }
}

// INCOMING ENVELOPE HANDLER
async function handleIncomingEnvelope(envelope) {
    // Avoid duplicate processing if already received
    if (messages.some(m => m.messageId === envelope.messageId)) {
        return;
    }

    let sender = contacts.get(envelope.senderId);
    if (!sender) {
        try {
            const keyResp = await fetch(`/api/user/keys?username=${encodeURIComponent(envelope.senderId)}`);
            if (keyResp.ok) {
                sender = await keyResp.json();
                contacts.set(envelope.senderId, sender);
                renderContactList();
            }
        } catch (_) {}
    }

    let decryptedText = "";
    let isError = false;
    let errorMessage = "";

    try {
        if (!sender) {
            throw new Error(`Người gửi '${envelope.senderId}' chưa có trong danh bạ khóa công khai.`);
        }

        let openResp;
        try {
            openResp = await fetch("/api/crypto/open-message", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    envelope: envelope,
                    senderSigPublicKey: sender.signingPublicKey,
                    myEncPrivateKey: currentUser.encryptionPrivateKey,
                    groupModulusP_Hex: currentUser.encryptionPublicKey.p_Hex,
                    isSender: false
                })
            });
        } catch (fetchOpenErr) {
            console.error("Lỗi fetch /api/crypto/open-message:", fetchOpenErr);
            throw new Error(`Mất kết nối máy chủ giải mã: ${fetchOpenErr.message}`);
        }

        if (!openResp.ok) {
            const err = await openResp.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${openResp.status}: Xác minh chữ ký hoặc giải mã thất bại.`);
        }

        const result = await openResp.json();
        decryptedText = result.plaintextMessage;
    } catch (err) {
        isError = true;
        errorMessage = err.message;
    }

    messages.push({
        messageId: envelope.messageId,
        isMe: false,
        senderId: envelope.senderId,
        recipientId: currentUser.userId,
        plaintext: decryptedText,
        isError: isError,
        errorMessage: errorMessage,
        envelope: envelope,
        timestamp: new Date()
    });

    if (currentRecipientId === envelope.senderId || !currentRecipientId) {
        currentRecipientId = envelope.senderId;
        updateRecipientHeader();
    }

    renderChatHistory();
    renderContactList();
}

// ==========================================================================
// ==========================================================================
// 8. RENDER MESSAGES WITH BEAUTIFUL MESSENGER GEOMETRY
// ==========================================================================

function renderChatHistory() {
    const container = document.getElementById("chat-messages");
    container.innerHTML = "";

    if (!currentRecipientId) {
        container.innerHTML = `
            <div class="chat-welcome-notice">
                <div class="welcome-logo-wrap"><img src="logo.png" class="welcome-app-logo" alt="Ri Tetsuya" /></div>
                <h3>Chào mừng bạn đến với Ri Tetsuya</h3>
                <p>Hãy chọn một liên hệ từ danh sách bên trái để bắt đầu cuộc trò chuyện được mã hóa đầu cuối ElGamal–AES.</p>
            </div>
        `;
        return;
    }

    const filtered = messages.filter(m =>
        (m.senderId === currentUser.userId && m.recipientId === currentRecipientId) ||
        (m.senderId === currentRecipientId && m.recipientId === currentUser.userId)
    );

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="chat-welcome-notice">
                <div class="welcome-logo-wrap"><img src="logo.png" class="welcome-app-logo" alt="Ri Tetsuya" /></div>
                <h3>Đoạn chat bảo mật với ${escapeHtml(currentRecipientId)}</h3>
                <p>Khóa phiên AES-256-GCM sinh ngẫu nhiên cho từng tin nhắn, bảo vệ bởi ElGamal và chứng thực bằng Chữ ký số ElGamal–SHA256.</p>
                <div class="welcome-sub-badge"><i class="fas fa-shield-alt"></i> Bảo mật đa lớp • Chống nghe lén • Chống giả mạo</div>
            </div>
        `;
        return;
    }

    filtered.forEach((msg) => {
        const row = document.createElement("div");
        row.className = `message-row ${msg.isMe ? "me" : "other"}`;

        // Avatar for recipient
        let avatarHtml = "";
        if (!msg.isMe) {
            avatarHtml = `<div class="message-avatar" id="msg-sender-av-${msg.messageId}"></div>`;
        }

        let bubbleContent = "";
        let metaButtons = "";

        if (msg.isError) {
            bubbleContent = `
                <div class="msg-bubble bubble-error">
                    <div class="bubble-error-title"><i class="fas fa-exclamation-triangle"></i> PHÁT HIỆN TẤN CÔNG / LỖI MẬT MÃ!</div>
                    <div>${escapeHtml(msg.errorMessage)}</div>
                </div>
            `;
            metaButtons = `<button class="btn-inspect-pill" onclick="openInspector('${msg.messageId}')" title="Mở Kính Lúp Mật Mã"><i class="fas fa-microscope"></i> Soi Mật Mã</button>`;
        } else {
            bubbleContent = `
                <div class="msg-bubble">
                    ${escapeHtml(msg.plaintext)}
                    ${msg.isTampered ? `<span class="tampered-tag"> [⚠️ Đã gửi bản tin bị can thiệp: ${escapeHtml(msg.tamperType)}]</span>` : ""}
                </div>
            `;
            metaButtons = `<button class="btn-inspect-pill" onclick="openInspector('${msg.messageId}')" title="Mở Kính Lúp Mật Mã"><i class="fas fa-microscope"></i> Soi Mật Mã</button>`;
        }

        const metaHtml = `
            <div class="msg-meta-row">
                <span class="msg-time">${new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                <span class="msg-e2ee-tag"><i class="fas fa-lock"></i> E2EE</span>
                ${metaButtons}
            </div>
        `;

        if (msg.isMe) {
            row.innerHTML = `<div class="bubble-wrap">${bubbleContent}${metaHtml}</div>`;
        } else {
            row.innerHTML = avatarHtml + `<div class="bubble-wrap">${bubbleContent}${metaHtml}</div>`;
        }

        container.appendChild(row);

        if (!msg.isMe) {
            const senderUser = contacts.get(msg.senderId);
            const avEl = document.getElementById(`msg-sender-av-${msg.messageId}`);
            renderAvatarIntoElement(avEl, msg.senderId, senderUser?.avatarUrl);
        }
    });

    container.scrollTop = container.scrollHeight;
}

function escapeHtml(text) {
    if (!text) return "";
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ==========================================================================
// 10. CRYPTO INSPECTOR MODAL
// ==========================================================================

window.openInspector = function(messageId) {
    const msg = messages.find(m => m.messageId === messageId);
    if (!msg) return;

    const modal = document.getElementById("inspector-modal");
    const body = document.getElementById("inspector-body");
    const env = msg.envelope;

    body.innerHTML = `
        <div class="insp-step-box">
            <h4><i class="fas fa-key"></i> 1. Bản Rõ &amp; Khóa Phiên AES-256 (CSPRNG)</h4>
            <table class="insp-step-table">
                <tr><td>Bản rõ gốc:</td><td><strong>${escapeHtml(msg.plaintext || "[Lỗi giải mã]")}</strong></td></tr>
                <tr><td>Khóa đối xứng K (32B):</td><td class="mono-inline break-all">${msg.inspection ? msg.inspection.sessionKeyHex : "[Bảo mật E2EE]"}</td></tr>
                <tr><td>Chuyển đổi u = OS2IP(K):</td><td class="mono-inline break-all">${msg.inspection ? msg.inspection.uValueHex : "--"}</td></tr>
                <tr><td>Biểu diễn m = (u + 1)²:</td><td class="mono-inline break-all">${msg.inspection ? msg.inspection.mValueHex : "--"}</td></tr>
            </table>
        </div>

        <div class="insp-step-box">
            <h4><i class="fas fa-user-lock"></i> 2. Khóa ElGamal Bảo Vệ Kép (Chương 2.3)</h4>
            <table class="insp-step-table">
                <tr><td>WB (Bảo vệ cho người nhận):</td><td class="mono-inline break-all">c1 = ${env.recipientKeyW.c1Hex.substring(0, 32)}...<br>c2 = ${env.recipientKeyW.c2Hex.substring(0, 32)}...</td></tr>
                <tr><td>WA (Bảo vệ cho người gửi):</td><td class="mono-inline break-all">c1 = ${env.senderKeyW.c1Hex.substring(0, 32)}...<br>c2 = ${env.senderKeyW.c2Hex.substring(0, 32)}...</td></tr>
            </table>
        </div>

        <div class="insp-step-box">
            <h4><i class="fas fa-lock"></i> 3. AES-256-GCM Payload &amp; Toàn Vẹn AAD (Chương 2.2)</h4>
            <table class="insp-step-table">
                <tr><td>Nonce ngẫu nhiên (12 byte):</td><td class="mono-inline break-all">${env.nonceBase64}</td></tr>
                <tr><td>Bản mã Ciphertext C:</td><td class="mono-inline break-all">${env.ciphertextBase64}</td></tr>
                <tr><td>Thẻ xác thực Auth Tag T (16 byte):</td><td class="mono-inline break-all">${env.authTagBase64}</td></tr>
            </table>
        </div>

        <div class="insp-step-box">
            <h4><i class="fas fa-file-signature"></i> 4. Chữ Ký Số ElGamal–SHA256 (Chương 3)</h4>
            <table class="insp-step-table">
                <tr><td>Dấu vân tay người ký:</td><td class="mono-inline break-all">${env.senderSigFingerprint}</td></tr>
                <tr><td>Thành phần r = g^k mod p:</td><td class="mono-inline break-all">${env.signature.rHex.substring(0, 32)}...</td></tr>
                <tr><td>Thành phần s = k⁻¹(h - xr):</td><td class="mono-inline break-all">${env.signature.sHex.substring(0, 32)}...</td></tr>
                <tr><td>Điều kiện xác minh:</td><td style="color: #31a24c; font-weight: bold;">g^h mod p ≡ y^r • r^s mod p  ${msg.isError ? "❌ THẤT BẠI" : "✔️ HỢP LỆ"}</td></tr>
            </table>
        </div>
    `;

    modal.style.display = "flex";
};

window.closeInspector = function() {
    document.getElementById("inspector-modal").style.display = "none";
};

// ==========================================================================
// 11. RIGHT INFO PANEL & ACCORDIONS
// ==========================================================================

function setupRightPanel() {
    const toggleBtn = document.getElementById("btn-toggle-info-panel");
    const exportBtn = document.getElementById("btn-export-keystore-panel");
    const rotateBtn = document.getElementById("btn-rotate-keys-panel");

    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            window.toggleInfoPanel();
        });
    }

    if (exportBtn) exportBtn.addEventListener("click", () => exportKeystoreAction());
    if (rotateBtn) rotateBtn.addEventListener("click", () => rotateKeysAction());

    const modalExportBtn = document.getElementById("btn-export-keystore-modal");
    if (modalExportBtn) modalExportBtn.addEventListener("click", () => exportKeystoreAction());
}

window.toggleAccordion = function(bodyId) {
    const body = document.getElementById(bodyId);
    const item = body.parentElement;
    item.classList.toggle("open");
};

function renderKeyManagementDetails() {
    document.getElementById("km-userid").innerText = currentUser.userId;
    document.getElementById("km-keyid").innerText = currentUser.keyId;
    document.getElementById("km-created").innerText = new Date(currentUser.createdAt).toLocaleString();
    document.getElementById("km-comb-fp").innerText = currentUser.combinedFingerprint;

    document.getElementById("km-enc-y").innerText = currentUser.encryptionPublicKey.y_Hex;
    document.getElementById("km-sig-y").innerText = currentUser.signingPublicKey.y_Hex;
}

async function exportKeystoreAction() {
    const passphrase = document.getElementById("export-passphrase").value;
    if (!passphrase) { alert("Vui lòng nhập mật khẩu xuất file!"); return; }

    try {
        const resp = await fetch("/api/crypto/export-keystore", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                userId: currentUser.userId,
                keyId: currentUser.keyId,
                createdAt: currentUser.createdAt,
                isActive: currentUser.isActive,
                encPk: currentUser.encryptionPublicKey,
                encSk: currentUser.encryptionPrivateKey,
                sigPk: currentUser.signingPublicKey,
                sigSk: currentUser.signingPrivateKey,
                passphrase: passphrase
            })
        });

        if (!resp.ok) throw new Error("Xuất Keystore thất bại.");
        const data = await resp.json();

        const blob = new Blob([data.keystoreJson], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${currentUser.userId}_keystore_backup.json`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (err) {
        alert("Lỗi xuất file: " + err.message);
    }
}

async function rotateKeysAction() {
    if (!confirm("Bạn có chắc chắn muốn THU HỒI bộ khóa cũ và tạo BỘ KHÓA MỚI (Key Rotation)?")) return;

    try {
        const resp = await fetch("/api/crypto/create-key-bundle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId: currentUser.userId, groupName: "rfc2048" })
        });

        if (!resp.ok) throw new Error("Không thể sinh khóa mới.");
        const newBundle = await resp.json();
        currentUser = newBundle;

        renderKeyManagementDetails();
        document.getElementById("my-fingerprint-display").innerText = currentUser.combinedFingerprint;

        const announcement = {
            userId: newBundle.userId,
            keyId: newBundle.keyId,
            createdAt: newBundle.createdAt,
            isActive: true,
            encryptionPublicKey: newBundle.encryptionPublicKey,
            signingPublicKey: newBundle.signingPublicKey,
            encryptionFingerprint: newBundle.encryptionFingerprint,
            signingFingerprint: newBundle.signingFingerprint,
            combinedFingerprint: newBundle.combinedFingerprint,
            avatarUrl: currentUser.avatarUrl || ""
        };

        await hubConnection.invoke("RotateKeys", announcement);
        alert("Đã tạo mới bộ khóa và phát thông báo dấu vân tay mới cho toàn hệ thống!");
    } catch (err) {
        alert("Lỗi thay đổi khóa: " + err.message);
    }
}

// ==========================================================================
// 12. VERIFY MODAL & OTHER MODALS
// ==========================================================================

function openVerifyModal() {
    if (!currentRecipientId || !contacts.has(currentRecipientId)) return;
    const contact = contacts.get(currentRecipientId);
    const modal = document.getElementById("verify-modal");
    const content = document.getElementById("verify-modal-content");

    content.innerHTML = `
        <div style="margin-bottom: 12px;">
            <p><strong>Người nhận:</strong> ${contact.userId}</p>
            <p><strong>Dấu vân tay kết hợp (Combined Fingerprint):</strong></p>
            <div class="mono-box">${contact.combinedFingerprint}</div>
        </div>
        <div style="margin-bottom: 12px;">
            <p><strong>Dấu vân tay Khóa Mã Hóa (ENC):</strong></p>
            <div class="mono-box">${contact.encryptionFingerprint}</div>
        </div>
        <div>
            <p><strong>Dấu vân tay Khóa Ký Số (SIG):</strong></p>
            <div class="mono-box">${contact.signingFingerprint}</div>
        </div>
        <p style="margin-top: 12px; font-size: 0.8rem; color: #0084ff;">
            💡 Khuyên dùng: Hãy đối chiếu trực tiếp chuỗi ký tự vân tay này với người bạn của bạn để đảm bảo không ai can thiệp!
        </p>
    `;

    modal.style.display = "flex";
}

window.closeVerifyModal = function() {
    document.getElementById("verify-modal").style.display = "none";
};

window.openTheoryModal = function() {
    document.getElementById("theory-modal").style.display = "flex";
    loadTheoryDemo("encrypt");
};

window.closeTheoryModal = function() {
    document.getElementById("theory-modal").style.display = "none";
};

window.openKeyMgmtModal = function() {
    document.getElementById("key-mgmt-modal").style.display = "flex";
};

window.closeKeyMgmtModal = function() {
    document.getElementById("key-mgmt-modal").style.display = "none";
};

window.loadTheoryDemo = async function(mode) {
    const btnEnc = document.getElementById("btn-theory-enc");
    const btnSig = document.getElementById("btn-theory-sig");

    if (mode === "signature") {
        btnSig.classList.add("active");
        btnEnc.classList.remove("active");
    } else {
        btnEnc.classList.add("active");
        btnSig.classList.remove("active");
    }

    try {
        const resp = await fetch(`/api/crypto/theory-demo?mode=${mode}`);
        const data = await resp.json();

        const paramsBox = document.getElementById("theory-params");
        let pHtml = `<strong>${data.algorithm}</strong><br>Tham số: `;
        for (const [k, v] of Object.entries(data.parameters)) {
            pHtml += `<span style="margin-right: 10px;">${k}=<strong>${v}</strong></span>`;
        }
        paramsBox.innerHTML = pHtml;

        const body = document.getElementById("theory-steps-body");
        body.innerHTML = "";
        data.steps.forEach(s => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${s.step}</td>
                <td><strong>${s.desc}</strong></td>
                <td><code>${s.formula}</code></td>
                <td>${s.result}</td>
            `;
            body.appendChild(tr);
        });
    } catch (err) {
        console.error("Lỗi tải lý thuyết:", err);
    }
};

// ==========================================================================
// 13. MONGODB BACKUP & PERSISTENCE MANAGEMENT
// ==========================================================================

let lastMongoStatus = null;

async function checkMongoStatus() {
    try {
        const resp = await fetch("/api/mongodb/status");
        if (!resp.ok) return;
        const status = await resp.json();
        lastMongoStatus = status;
        updateMongoStatusUI(status);
    } catch (err) {
        console.warn("Không thể kiểm tra trạng thái MongoDB:", err);
    }
}

function updateMongoStatusUI(status) {
    const dot = document.getElementById("mongo-status-dot");
    const text = document.getElementById("mongo-status-text");
    const pill = document.getElementById("mongo-status-pill");

    if (dot && text) {
        if (status.isConnected) {
            dot.className = "mongo-status-dot dot-online";
            text.innerText = `MongoDB: Đã kết nối (${status.databaseName || "RiTetsuyaDb"})`;
            if (pill) pill.title = "Đã kết nối MongoDB. Nhấp để xem chi tiết sao lưu.";
        } else {
            dot.className = "mongo-status-dot dot-offline";
            text.innerText = "MongoDB: Chưa kết nối (Local Fallback)";
            if (pill) pill.title = "MongoDB chưa kết nối. Dữ liệu tạm thời lưu bộ nhớ cục bộ. Nhấp để kết nối.";
        }
    }

    const modalBanner = document.getElementById("mongo-modal-status-banner");
    const modalTitle = document.getElementById("mongo-modal-status-title");
    const modalDesc = document.getElementById("mongo-modal-status-desc");
    const statUsers = document.getElementById("mongo-stat-users");
    const statMessages = document.getElementById("mongo-stat-messages");
    const inputConn = document.getElementById("mongo-input-connstr");
    const inputDb = document.getElementById("mongo-input-dbname");

    if (modalBanner) {
        modalBanner.className = "mongo-banner " + (status.isConnected ? "status-connected" : "status-disconnected");
    }
    if (modalTitle) {
        modalTitle.innerText = status.isConnected ? "Đã kết nối MongoDB thành công!" : "Chưa kết nối với MongoDB";
    }
    if (modalDesc) {
        if (status.isConnected) {
            modalDesc.innerText = `Hệ thống đang sao lưu tự động vào database '${status.databaseName}'. Bảo mật E2EE chuẩn Zero-Knowledge.`;
        } else {
            modalDesc.innerText = status.lastError 
                ? `Lỗi: ${status.lastError} (Đang dùng cơ chế In-Memory/JSON an toàn)` 
                : "Hệ thống đang hoạt động ở chế độ bộ nhớ cục bộ an toàn (In-Memory / Local Storage).";
        }
    }
    if (statUsers) statUsers.innerText = status.usersCount || 0;
    if (statMessages) statMessages.innerText = status.messagesCount || 0;

    if (inputConn && !inputConn.value) {
        inputConn.value = status.connectionString || "mongodb://localhost:27017";
    }
    if (inputDb && !inputDb.value) {
        inputDb.value = status.databaseName || "RiTetsuyaDb";
    }
}

window.openMongoModal = async function() {
    const modal = document.getElementById("mongodb-modal");
    if (!modal) return;
    modal.style.display = "flex";
    await checkMongoStatus();
    if (lastMongoStatus) {
        const inputConn = document.getElementById("mongo-input-connstr");
        const inputDb = document.getElementById("mongo-input-dbname");
        if (inputConn && lastMongoStatus.connectionString) inputConn.value = lastMongoStatus.connectionString;
        if (inputDb && lastMongoStatus.databaseName) inputDb.value = lastMongoStatus.databaseName;
    }
};

window.closeMongoModal = function() {
    const modal = document.getElementById("mongodb-modal");
    if (modal) modal.style.display = "none";
};

window.saveMongoConfig = async function() {
    const inputConn = document.getElementById("mongo-input-connstr");
    const inputDb = document.getElementById("mongo-input-dbname");
    const connStr = inputConn ? inputConn.value.trim() : "";
    const dbName = inputDb ? inputDb.value.trim() : "";

    if (!connStr) {
        alert("Vui lòng nhập chuỗi kết nối MongoDB (ví dụ: mongodb://localhost:27017 hoặc mongodb+srv://...)");
        return;
    }

    const saveBtn = document.querySelector("#mongodb-modal .msg-btn-primary");
    const originalBtnText = saveBtn ? saveBtn.innerHTML : "";
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang kết nối...';
    }

    try {
        const resp = await fetch("/api/mongodb/configure", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ connectionString: connStr, databaseName: dbName || "RiTetsuyaDb" })
        });

        const status = await resp.json();
        lastMongoStatus = status;
        updateMongoStatusUI(status);

        if (status.isConnected) {
            alert(`🎉 Kết nối MongoDB thành công!\nDatabase: ${status.databaseName}\nTài khoản đã đồng bộ: ${status.usersCount}\nTin nhắn E2EE đã sao lưu: ${status.messagesCount}`);
        } else {
            alert(`⚠️ Không thể kết nối tới MongoDB với thông số vừa nhập.\n\nChi tiết lỗi: ${status.lastError || "Hết thời gian chờ kết nối"}\n\nLưu ý: Hệ thống vẫn duy trì hoạt động bình thường qua bộ nhớ cục bộ an toàn.`);
        }
    } catch (err) {
        alert("Lỗi cấu hình MongoDB: " + err.message);
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.innerHTML = originalBtnText;
        }
    }
};

// ==========================================================================
// 14. E2EE CHAT HISTORY RESTORATION FROM MONGODB
// ==========================================================================

async function loadChatHistoryFromMongo(recipientId) {
    if (!currentUser || !recipientId) return;
    try {
        const resp = await fetch(`/api/chat/history?user1=${encodeURIComponent(currentUser.userId)}&user2=${encodeURIComponent(recipientId)}`);
        if (!resp.ok) return;
        const envelopes = await resp.json();
        if (!Array.isArray(envelopes) || envelopes.length === 0) return;

        const newEnvelopes = envelopes.filter(env => !messages.some(m => m.messageId === env.messageId));
        if (newEnvelopes.length === 0) return;

        const decryptedMessages = await Promise.all(newEnvelopes.map(async (env) => {
            const isMe = (env.senderId.toLowerCase() === currentUser.userId.toLowerCase());
            let decryptedText = "";
            let isError = false;
            let errorMessage = "";

            try {
                let senderSigPk = isMe 
                    ? currentUser.signingPublicKey 
                    : contacts.get(env.senderId)?.signingPublicKey;

                if (!senderSigPk) {
                    try {
                        const keyResp = await fetch(`/api/user/keys?username=${encodeURIComponent(env.senderId)}`);
                        if (keyResp.ok) {
                            const ann = await keyResp.json();
                            contacts.set(env.senderId, ann);
                            senderSigPk = ann.signingPublicKey;
                        }
                    } catch (_) {}
                }

                if (!senderSigPk) {
                    throw new Error(`Chưa có khóa công khai của người gửi ${env.senderId}`);
                }

                const openResp = await fetch("/api/crypto/open-message", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        envelope: env,
                        senderSigPublicKey: senderSigPk,
                        myEncPrivateKey: currentUser.encryptionPrivateKey,
                        groupModulusP_Hex: currentUser.encryptionPublicKey.p_Hex,
                        isSender: isMe
                    })
                });

                if (!openResp.ok) {
                    const errData = await openResp.json().catch(() => ({}));
                    throw new Error(errData.error || `HTTP ${openResp.status}: Lỗi giải mã`);
                }

                const decResult = await openResp.json();
                decryptedText = decResult.plaintextMessage;
            } catch (err) {
                isError = true;
                errorMessage = err.message;
            }

            return {
                messageId: env.messageId,
                isMe: isMe,
                senderId: env.senderId,
                recipientId: env.recipientId,
                plaintext: decryptedText,
                isError: isError,
                errorMessage: errorMessage,
                envelope: env,
                timestamp: new Date(env.timestamp || Date.now())
            };
        }));

        let hasNew = false;
        for (const dm of decryptedMessages) {
            if (!messages.some(m => m.messageId === dm.messageId)) {
                messages.push(dm);
                hasNew = true;
            }
        }

        if (hasNew) {
            messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            if (currentRecipientId === recipientId) {
                renderChatHistory();
            }
            renderContactList();
        }
    } catch (err) {
        console.warn("Lỗi tải lịch sử tin nhắn từ MongoDB:", err);
    }
}
