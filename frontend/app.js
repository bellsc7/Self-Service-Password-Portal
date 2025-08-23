let recaptchaForgotId;
let recaptchaUnlockId;

// ฟังก์ชันนี้จะถูกเรียกโดย Script ของ Google reCAPTCHA เมื่อโหลดเสร็จ
// เราต้องวางฟังก์ชันนี้ไว้นอก DOMContentLoaded เพื่อให้ Google มองเห็นเป็น Global function
function onRecaptchaLoad() {
    // ใส่ Site Key ของคุณตรงนี้
    const siteKey = "6LenRa8rAAAAAOp2hg9V1p3ciijqBOmsT279WfOQ"; // Your Site Key
    
    // วาด reCAPTCHA ลงใน div ที่เราเตรียมไว้
    if (document.getElementById('recaptcha-forgot')) {
        recaptchaForgotId = grecaptcha.render('recaptcha-forgot', {
            'sitekey': siteKey
        });
    }
    if (document.getElementById('recaptcha-unlock')) {
        recaptchaUnlockId = grecaptcha.render('recaptcha-unlock', {
            'sitekey': siteKey
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // --- Global Variables & Constants ---
    const API_BASE_URL = 'http://127.0.0.1:8000';
    let currentUsername = '';

    // --- Element References ---
    const mainMenu = document.getElementById('main-menu');
    const formsContainer = document.getElementById('forms-container');
    const enrollmentSection = document.getElementById('enrollment-section');
    const userGuideSection = document.getElementById('user-guide-section');
    
    // Navigation
    const navResetBtn = document.getElementById('nav-reset-password');
    const navUnlockBtn = document.getElementById('nav-unlock-account');
    const navEnrollmentBtn = document.getElementById('nav-enrollment');
    const navUserGuideBtn = document.getElementById('nav-user-guide');
    const backToMenuBtns = document.querySelectorAll('.back-to-menu');
    
    // Form Sections
    const forgotPasswordSection = document.getElementById('forgot-password-section');
    const unlockAccountSection = document.getElementById('unlock-account-section');
    
    // Individual Forms
    const forgotForm = document.getElementById('forgot-form');
    const resetForm = document.getElementById('reset-form');
    const unlockRequestForm = document.getElementById('unlock-request-form');
    const unlockConfirmForm = document.getElementById('unlock-confirm-form');
    const loginForm = document.getElementById('login-form');
    const profileView = document.getElementById('profile-view');
    const updateProfileForm = document.getElementById('update-profile-form');

    // Message Areas
    const messageArea = document.getElementById('message-area');
    const messageAreaEnroll = document.getElementById('message-area-enroll');

    // --- Helper Functions ---
    function showMessage(message, type = 'success') {
        messageArea.textContent = message;
        messageArea.className = `message-area ${type}`;
    }

    function showEnrollMessage(message, type = 'success') {
        messageAreaEnroll.textContent = message;
        messageAreaEnroll.className = `message-area ${type}`;
    }

    function clearMessages() {
        messageArea.textContent = '';
        messageArea.className = 'message-area';
        messageAreaEnroll.textContent = '';
        messageAreaEnroll.className = 'message-area';
    }

    function showContentSection(sectionToShow) {
        mainMenu.style.display = 'none';
        formsContainer.style.display = 'none';
        enrollmentSection.style.display = 'none';
        userGuideSection.style.display = 'none';
        sectionToShow.style.display = 'block';
        clearMessages();
    }
    
    function resetRecaptchaWidgets() {
        if (typeof grecaptcha !== 'undefined') {
            if (recaptchaForgotId !== undefined) grecaptcha.reset(recaptchaForgotId);
            if (recaptchaUnlockId !== undefined) grecaptcha.reset(recaptchaUnlockId);
        }
    }

    // --- Navigation Logic ---
    navResetBtn.addEventListener('click', (e) => { 
        e.preventDefault(); 
        showContentSection(formsContainer);
        forgotPasswordSection.style.display = 'block';
        unlockAccountSection.style.display = 'none';
    });

    navUnlockBtn.addEventListener('click', (e) => { 
        e.preventDefault(); 
        showContentSection(formsContainer);
        forgotPasswordSection.style.display = 'none';
        unlockAccountSection.style.display = 'block';
    });

    navEnrollmentBtn.addEventListener('click', (e) => { e.preventDefault(); showContentSection(enrollmentSection); });
    
    navUserGuideBtn.addEventListener('click', (e) => { e.preventDefault(); showContentSection(userGuideSection); });

    backToMenuBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            formsContainer.style.display = 'none';
            enrollmentSection.style.display = 'none';
            userGuideSection.style.display = 'none';
            mainMenu.style.display = 'block';
            
            localStorage.removeItem('userToken');
            profileView.style.display = 'none';
            loginForm.style.display = 'block';
            
            document.querySelectorAll('form').forEach(form => form.reset());
            clearMessages();
            resetRecaptchaWidgets();
        });
    });

    // --- Forgot Password Flow ---
    forgotForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const recaptcha_token = grecaptcha.getResponse(recaptchaForgotId);
        if (!recaptcha_token) {
            return showMessage("Please complete the reCAPTCHA.", "error");
        }
        
        currentUsername = document.getElementById('username-forgot').value;
        showMessage('Sending request...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/api/password/forgot-request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: currentUsername,
                    recaptcha_token: recaptcha_token
                }),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'An unknown error occurred.');
            
            showMessage(data.message);
            forgotForm.style.display = 'none';
            resetForm.style.display = 'block';
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
            grecaptcha.reset(recaptchaForgotId);
        }
    });

    resetForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const otp = document.getElementById('otp-reset').value;
        const new_password = document.getElementById('new_password').value;
        const confirm_password = document.getElementById('confirm_password').value;

        if (new_password !== confirm_password) {
            return showMessage('New passwords do not match.', 'error');
        }
        showMessage('Resetting password...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/api/password/reset`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUsername, otp, new_password }),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'An unknown error occurred.');

            resetForm.style.display = 'none';
            forgotForm.style.display = 'block';
            forgotForm.reset();
            showMessage(data.message);
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    });

    // --- Unlock Account Flow ---
    unlockRequestForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const recaptcha_token = grecaptcha.getResponse(recaptchaUnlockId);
        if (!recaptcha_token) {
            return showMessage("Please complete the reCAPTCHA.", "error");
        }

        currentUsername = document.getElementById('username-unlock').value;
        showMessage('Sending unlock request...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/api/account/unlock-request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: currentUsername,
                    recaptcha_token: recaptcha_token
                }),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'An unknown error occurred.');
            
            showMessage(data.message);
            unlockRequestForm.style.display = 'none';
            unlockConfirmForm.style.display = 'block';
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
            grecaptcha.reset(recaptchaUnlockId);
        }
    });
    
    unlockConfirmForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const otp = document.getElementById('otp-unlock').value;
        showMessage('Unlocking account...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/api/account/unlock-confirm`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: currentUsername, otp: otp }),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail);

            unlockConfirmForm.style.display = 'none';
            unlockRequestForm.style.display = 'block';
            unlockRequestForm.reset();
            showMessage(data.message);
        } catch (error) {
            showMessage(`Error: ${error.message}`, 'error');
        }
    });

    // --- Enrollment Logic ---
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showEnrollMessage('Logging in...', 'info');
        const username = document.getElementById('username-login').value;
        const password = document.getElementById('password-login').value;

        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail);

            localStorage.setItem('userToken', data.access_token);
            await fetchAndDisplayProfile();
        } catch (error) {
            showEnrollMessage(`Login failed: ${error.message}`, 'error');
        }
    });

    async function fetchAndDisplayProfile() {
        const token = localStorage.getItem('userToken');
        if (!token) return;
        showEnrollMessage('Loading profile...', 'info');
        try {
            const response = await fetch(`${API_BASE_URL}/api/user/me`, {
                method: 'GET',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail);

            document.getElementById('profile-displayName').textContent = data.displayName || 'N/A';
            document.getElementById('profile-email').textContent = data.email || 'N/A';
            document.getElementById('profile-telephone').textContent = data.telephone || 'N/A';
            document.getElementById('personal-email').value = data.personal_email || '';

            loginForm.style.display = 'none';
            profileView.style.display = 'block';
            showEnrollMessage('Profile loaded successfully.', 'success');
        } catch (error) {
            showEnrollMessage(`Error loading profile: ${error.message}`, 'error');
            localStorage.removeItem('userToken');
        }
    }

    updateProfileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showEnrollMessage('Saving changes...', 'info');
        const token = localStorage.getItem('userToken');
        const personal_email = document.getElementById('personal-email').value;

        try {
            const response = await fetch(`${API_BASE_URL}/api/user/me`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ personal_email })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail);
            showEnrollMessage(data.message, 'success');
        } catch (error) {
            showMessage(`Error saving changes: ${error.message}`, 'error');
        }
    });
});