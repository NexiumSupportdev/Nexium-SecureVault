class CryptoManager {
    constructor() {
        this.keyCache = new Map();
    }

    async deriveKey(password, salt) {
        const cacheKey = password + btoa(String.fromCharCode(...salt));
        if (this.keyCache.has(cacheKey)) {
            return this.keyCache.get(cacheKey);
        }

        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 150000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        this.keyCache.set(cacheKey, key);
        return key;
    }
    
    async encryptData(data, password) {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const key = await this.deriveKey(password, salt);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(data)
        );
        
        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);
        
        return btoa(String.fromCharCode(...result));
    }
    
    async decryptData(encryptedData, password) {
        try {
            const data = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
            const salt = data.slice(0, 16);
            const iv = data.slice(16, 28);
            const encrypted = data.slice(28);
            
            const key = await this.deriveKey(password, salt);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error('Decryption failed - invalid password or corrupted data');
        }
    }

    generateSecureKey() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }

    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hash)));
    }

    clearCache() {
        this.keyCache.clear();
    }
}