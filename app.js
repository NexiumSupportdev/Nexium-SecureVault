class NexiumApp {
    constructor() {
        this.cryptoManager = new CryptoManager();
        this.masterPassword = null;
        this.masterKeyHash = null;
        this.encryptionKey = null;
        this.passwords = [];
        this.notes = [];
        this.isFirstTime = false;
        this.failedAttempts = 0;
        this.maxAttempts = 3;
        this.lockoutTime = 5 * 60 * 1000; // 5 minutes
        this.init();
    }

    init() {
        this.checkFirstTimeSetup();
        this.loadData();
        if (this.isFirstTime) {
            this.showSetupModal();
        } else {
            this.showAuthModal();
        }
    }

    checkFirstTimeSetup() {
        const masterHash = localStorage.getItem('nexium_master_hash');
        this.isFirstTime = !masterHash;
    }

    showSetupModal() {
        document.getElementById('setup-modal').style.display = 'flex';
        document.getElementById('auth-modal').style.display = 'none';
    }

    showAuthModal() {
        if (this.isLocked()) {
            this.showLockoutMessage();
            return;
        }
        document.getElementById('auth-modal').style.display = 'flex';
        document.getElementById('setup-modal').style.display = 'none';
    }

    isLocked() {
        const lockoutEnd = localStorage.getItem('nexium_lockout_end');
        if (lockoutEnd && Date.now() < parseInt(lockoutEnd)) {
            return true;
        }
        return false;
    }

    showLockoutMessage() {
        const lockoutEnd = localStorage.getItem('nexium_lockout_end');
        const remainingTime = Math.ceil((parseInt(lockoutEnd) - Date.now()) / 1000 / 60);
        alert(`Account locked. Try again in ${remainingTime} minutes.`);
    }

    async setupMasterPassword() {
        const password = document.getElementById('setup-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }

        const strength = this.checkPasswordStrength(password);
        if (strength.score < 70) {
            alert('Password is too weak. Please use a stronger password.');
            return;
        }

        try {
            this.masterKeyHash = await this.cryptoManager.hashPassword(password);
            this.encryptionKey = this.cryptoManager.generateSecureKey();
            
            localStorage.setItem('nexium_master_hash', this.masterKeyHash);
            localStorage.setItem('nexium_encryption_key', await this.cryptoManager.encryptData(this.encryptionKey, password));
            
            this.masterPassword = password;
            this.isFirstTime = false;
            
            document.getElementById('setup-modal').style.display = 'none';
            this.showSuccessMessage('Master password created successfully!');
            
        } catch (error) {
            alert('Error setting up master password: ' + error.message);
        }
    }

    async authenticate() {
        const password = document.getElementById('master-password').value;
        
        if (!password) {
            alert('Please enter your master password');
            return;
        }

        try {
            const storedHash = localStorage.getItem('nexium_master_hash');
            const inputHash = await this.cryptoManager.hashPassword(password);
            
            if (storedHash !== inputHash) {
                this.failedAttempts++;
                
                if (this.failedAttempts >= this.maxAttempts) {
                    const lockoutEnd = Date.now() + this.lockoutTime;
                    localStorage.setItem('nexium_lockout_end', lockoutEnd.toString());
                    alert('Too many failed attempts. Account locked for 5 minutes.');
                    document.getElementById('auth-modal').style.display = 'none';
                    return;
                }
                
                alert(`Invalid password. ${this.maxAttempts - this.failedAttempts} attempts remaining.`);
                document.getElementById('master-password').value = '';
                return;
            }

            // Successful authentication
            this.masterPassword = password;
            this.failedAttempts = 0;
            localStorage.removeItem('nexium_lockout_end');
            
            // Decrypt the encryption key
            const encryptedKey = localStorage.getItem('nexium_encryption_key');
            this.encryptionKey = await this.cryptoManager.decryptData(encryptedKey, password);
            
            document.getElementById('auth-modal').style.display = 'none';
            await this.loadPasswords();
            await this.loadNotes();
            
            this.showSuccessMessage('Welcome back!');
            
        } catch (error) {
            alert('Authentication failed: ' + error.message);
        }
    }

    checkPasswordStrength(password) {
        let score = 0;
        const feedback = [];

        // Length check
        if (password.length >= 12) score += 25;
        else if (password.length >= 8) score += 15;
        else feedback.push("Use at least 8 characters");

        // Character variety
        if (/[a-z]/.test(password)) score += 15;
        else feedback.push("Add lowercase letters");

        if (/[A-Z]/.test(password)) score += 15;
        else feedback.push("Add uppercase letters");

        if (/\d/.test(password)) score += 15;
        else feedback.push("Add numbers");

        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 20;
        else feedback.push("Add special characters");

        // Common passwords
        const common = ['password', '123456', 'qwerty', 'admin'];
        if (common.includes(password.toLowerCase())) {
            score -= 30;
            feedback.push("Avoid common passwords");
        }

        let strength = 'Weak';
        if (score >= 80) strength = 'Strong';
        else if (score >= 60) strength = 'Medium';

        return { score: Math.max(0, score), strength, feedback };
    }

    generateStrongPassword(length = 16) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }

    async savePassword() {
        if (!this.masterPassword || !this.encryptionKey) {
            this.showAuthModal();
            return;
        }

        const title = document.getElementById('site-title').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('site-password').value;
        const category = document.getElementById('category').value;
        const url = document.getElementById('site-url').value;

        if (!title || !password) {
            alert('Title and password are required!');
            return;
        }

        try {
            const passwordData = {
                id: Date.now(),
                title: await this.cryptoManager.encryptData(title, this.encryptionKey),
                username: await this.cryptoManager.encryptData(username, this.encryptionKey),
                password: await this.cryptoManager.encryptData(password, this.encryptionKey),
                url: await this.cryptoManager.encryptData(url, this.encryptionKey),
                category: await this.cryptoManager.encryptData(category, this.encryptionKey),
                createdAt: new Date().toISOString()
            };

            this.passwords.push(passwordData);
            await this.saveDataToFile();
            await this.displayPasswords();
            this.clearPasswordForm();
            this.showSuccessMessage('Password saved successfully!');
        } catch (error) {
            alert('Error saving password: ' + error.message);
        }
    }

    async saveNote() {
        if (!this.masterPassword || !this.encryptionKey) {
            this.showAuthModal();
            return;
        }

        const title = document.getElementById('note-title').value;
        const content = document.getElementById('note-content').value;
        const category = document.getElementById('note-category').value;
        const tags = document.getElementById('note-tags').value;

        if (!title || !content) {
            alert('Title and content are required!');
            return;
        }

        try {
            const noteData = {
                id: Date.now(),
                title: await this.cryptoManager.encryptData(title, this.encryptionKey),
                content: await this.cryptoManager.encryptData(content, this.encryptionKey),
                category: await this.cryptoManager.encryptData(category, this.encryptionKey),
                tags: await this.cryptoManager.encryptData(tags, this.encryptionKey),
                createdAt: new Date().toISOString()
            };

            this.notes.push(noteData);
            await this.saveDataToFile();
            await this.displayNotes();
            this.clearNoteForm();
            this.showSuccessMessage('Note saved successfully!');
        } catch (error) {
            alert('Error saving note: ' + error.message);
        }
    }

    async displayPasswords() {
        const container = document.getElementById('passwords-container');
        container.innerHTML = '';

        if (this.passwords.length === 0) {
            container.innerHTML = '<p class="empty-state">No passwords saved yet. Add your first password above!</p>';
            return;
        }

        for (const pwd of this.passwords) {
            try {
                const title = await this.cryptoManager.decryptData(pwd.title, this.encryptionKey);
                const username = await this.cryptoManager.decryptData(pwd.username, this.encryptionKey);
                const category = await this.cryptoManager.decryptData(pwd.category, this.encryptionKey);
                const url = await this.cryptoManager.decryptData(pwd.url, this.encryptionKey);
                
                const div = document.createElement('div');
                div.className = 'password-item glass-card';
                div.innerHTML = `
                    <div class="password-header">
                        <h4>${title}</h4>
                        <span class="category-tag">${category}</span>
                    </div>
                    <p><strong>Username:</strong> ${username}</p>
                    <p><strong>URL:</strong> ${url}</p>
                    <p><strong>Password:</strong> <span id="pwd-${pwd.id}">••••••••</span></p>
                    <div class="password-actions">
                        <button class="btn-show" onclick="app.togglePassword(${pwd.id})">👁️ Show</button>
                        <button class="btn-copy" onclick="app.copyPassword(${pwd.id})">📋 Copy</button>
                        <button class="btn-delete" onclick="app.deletePassword(${pwd.id})">🗑️ Delete</button>
                    </div>
                `;
                container.appendChild(div);
            } catch (e) {
                console.error('Failed to decrypt password:', e);
            }
        }
    }

    async displayNotes() {
        const container = document.getElementById('notes-container');
        container.innerHTML = '';

        if (this.notes.length === 0) {
            container.innerHTML = '<p class="empty-state">No notes saved yet. Create your first secure note above!</p>';
            return;
        }

        for (const note of this.notes) {
            try {
                const title = await this.cryptoManager.decryptData(note.title, this.encryptionKey);
                const category = await this.cryptoManager.decryptData(note.category, this.encryptionKey);
                const content = await this.cryptoManager.decryptData(note.content, this.encryptionKey);
                
                const div = document.createElement('div');
                div.className = 'note-item glass-card';
                div.innerHTML = `
                    <div class="note-header">
                        <h4>${title}</h4>
                        <span class="category-tag">${category}</span>
                    </div>
                    <p class="note-preview">${content.substring(0, 100)}${content.length > 100 ? '...' : ''}</p>
                    <div class="note-actions">
                        <button class="btn-view" onclick="app.viewNote(${note.id})">👁️ View</button>
                        <button class="btn-edit" onclick="app.editNote(${note.id})">✏️ Edit</button>
                        <button class="btn-delete" onclick="app.deleteNote(${note.id})">🗑️ Delete</button>
                    </div>
                `;
                container.appendChild(div);
            } catch (e) {
                console.error('Failed to decrypt note:', e);
            }
        }
    }

    async saveDataToFile() {
        const data = {
            passwords: this.passwords,
            notes: this.notes,
            timestamp: new Date().toISOString(),
            version: '1.0.0'
        };
        
        // Save to localStorage as backup
        localStorage.setItem('nexium_vault_data', JSON.stringify(data));
        
        // Create downloadable JSON file
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        // Auto-save to downloads (if supported)
        if ('showSaveFilePicker' in window) {
            try {
                const fileHandle = await window.showSaveFilePicker({
                    suggestedName: `nexium-vault-${new Date().toISOString().split('T')[0]}.json`,
                    types: [{
                        description: 'JSON files',
                        accept: { 'application/json': ['.json'] }
                    }]
                });
                const writable = await fileHandle.createWritable();
                await writable.write(blob);
                await writable.close();
            } catch (e) {
                // User cancelled or error occurred
            }
        }
    }

    loadData() {
        const data = localStorage.getItem('nexium_vault_data');
        if (data) {
            const parsed = JSON.parse(data);
            this.passwords = parsed.passwords || [];
            this.notes = parsed.notes || [];
        } else {
            this.passwords = [];
            this.notes = [];
        }
    }

    async togglePassword(id) {
        const element = document.getElementById(`pwd-${id}`);
        const password = this.passwords.find(p => p.id === id);
        
        if (element.textContent === '••••••••') {
            try {
                const decrypted = await this.cryptoManager.decryptData(password.password, this.encryptionKey);
                element.textContent = decrypted;
                setTimeout(() => {
                    element.textContent = '••••••••';
                }, 10000); // Hide after 10 seconds
            } catch (e) {
                alert('Failed to decrypt password');
            }
        } else {
            element.textContent = '••••••••';
        }
    }

    async copyPassword(id) {
        const password = this.passwords.find(p => p.id === id);
        try {
            const decrypted = await this.cryptoManager.decryptData(password.password, this.encryptionKey);
            await navigator.clipboard.writeText(decrypted);
            this.showSuccessMessage('Password copied to clipboard!');
        } catch (e) {
            alert('Failed to copy password');
        }
    }

    deletePassword(id) {
        if (confirm('Are you sure you want to delete this password?')) {
            this.passwords = this.passwords.filter(p => p.id !== id);
            this.saveDataToFile();
            this.displayPasswords();
            this.showSuccessMessage('Password deleted successfully!');
        }
    }

    deleteNote(id) {
        if (confirm('Are you sure you want to delete this note?')) {
            this.notes = this.notes.filter(n => n.id !== id);
            this.saveDataToFile();
            this.displayNotes();
            this.showSuccessMessage('Note deleted successfully!');
        }
    }

    showSuccessMessage(message) {
        const toast = document.createElement('div');
        toast.className = 'toast success';
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => document.body.removeChild(toast), 300);
        }, 3000);
    }

    clearPasswordForm() {
        document.getElementById('site-title').value = '';
        document.getElementById('username').value = '';
        document.getElementById('site-password').value = '';
        document.getElementById('site-url').value = '';
        document.getElementById('category').value = '';
    }

    clearNoteForm() {
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('note-category').value = '';
        document.getElementById('note-tags').value = '';
    }

    async loadPasswords() {
        await this.displayPasswords();
    }

    async loadNotes() {
        await this.displayNotes();
    }

    logout() {
        this.masterPassword = null;
        this.encryptionKey = null;
        this.cryptoManager.clearCache();
        this.passwords = [];
        this.notes = [];
        this.showAuthModal();
        this.showSuccessMessage('Logged out successfully!');
    }

    async exportData() {
        if (!this.masterPassword) {
            this.showAuthModal();
            return;
        }

        const data = {
            passwords: this.passwords,
            notes: this.notes,
            exportDate: new Date().toISOString(),
            version: '1.0.0'
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nexium-vault-backup-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showSuccessMessage('Data exported successfully!');
    }

    async importData() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            try {
                const text = await file.text();
                const data = JSON.parse(text);
                
                if (data.passwords && data.notes) {
                    if (confirm('This will replace all current data. Continue?')) {
                        this.passwords = data.passwords;
                        this.notes = data.notes;
                        await this.saveDataToFile();
                        await this.displayPasswords();
                        await this.displayNotes();
                        this.showSuccessMessage('Data imported successfully!');
                    }
                } else {
                    alert('Invalid backup file format');
                }
            } catch (error) {
                alert('Error importing data: ' + error.message);
            }
        };
        
        input.click();
    }
}

// Global functions
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.getElementById(tabName).classList.add('active');
    event.target.classList.add('active');
}

function checkPassword() {
    const password = document.getElementById('password-input').value;
    const result = app.checkPasswordStrength(password);
    
    document.getElementById('strength-text').textContent = 
        `Strength: ${result.strength} (${result.score}/100)`;
    
    const strengthBar = document.getElementById('strength-bar');
    strengthBar.className = `strength-bar strength-${result.strength.toLowerCase()}`;
    
    const feedbackList = document.getElementById('feedback-list');
    feedbackList.innerHTML = '';
    result.feedback.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        feedbackList.appendChild(li);
    });
}

function generatePassword() {
    const password = app.generateStrongPassword();
    document.getElementById('password-input').value = password;
    checkPassword();
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    input.type = input.type === 'password' ? 'text' : 'password';
}

function authenticate() {
    app.authenticate();
}

function setupMasterPassword() {
    app.setupMasterPassword();
}

function savePassword() {
    app.savePassword();
}

function saveNote() {
    app.saveNote();
}

function logout() {
    app.logout();
}

function exportData() {
    app.exportData();
}

function importData() {
    app.importData();
}

// Initialize app
const app = new NexiumApp();
