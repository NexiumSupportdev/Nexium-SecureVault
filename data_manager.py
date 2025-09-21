import json
import os
from datetime import datetime
from crypto_manager import CryptoManager

class DataManager:
    def __init__(self, data_path: str = "nexium_vault.json"):
        self.data_path = data_path
        self.crypto = CryptoManager()
        self.master_hash_path = "nexium_master.hash"
        self.encryption_key = None
    
    def setup_master_password(self, password: str) -> str:
        """Setup master password and return encryption key"""
        import hashlib
        import secrets
        
        # Hash the master password
        master_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'nexium_salt', 100000)
        
        # Generate encryption key
        encryption_key = secrets.token_urlsafe(32)
        
        # Save master hash
        with open(self.master_hash_path, 'wb') as f:
            f.write(master_hash)
        
        # Save encrypted encryption key
        encrypted_key = self.crypto.encrypt_data(encryption_key, password)
        with open(self.master_hash_path + '.key', 'w') as f:
            f.write(encrypted_key)
        
        self.encryption_key = encryption_key
        return encryption_key
    
    def verify_master_password(self, password: str) -> bool:
        """Verify master password and load encryption key"""
        import hashlib
        
        if not os.path.exists(self.master_hash_path):
            return False
        
        # Hash input password
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'nexium_salt', 100000)
        
        # Compare with stored hash
        with open(self.master_hash_path, 'rb') as f:
            stored_hash = f.read()
        
        if input_hash == stored_hash:
            # Load encryption key
            with open(self.master_hash_path + '.key', 'r') as f:
                encrypted_key = f.read()
            
            self.encryption_key = self.crypto.decrypt_data(encrypted_key, password)
            return True
        
        return False
    
    def is_first_time(self) -> bool:
        """Check if this is first time setup"""
        return not os.path.exists(self.master_hash_path)
    
    def load_data(self) -> dict:
        """Load encrypted data from JSON file"""
        if not os.path.exists(self.data_path):
            return {'passwords': [], 'notes': [], 'version': '1.0.0'}
        
        try:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {'passwords': [], 'notes': [], 'version': '1.0.0'}
    
    def save_data(self, data: dict):
        """Save encrypted data to JSON file"""
        data['timestamp'] = datetime.now().isoformat()
        data['version'] = '1.0.0'
        
        with open(self.data_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def add_password(self, title: str, username: str, password: str, 
                    url: str = "", category: str = "", tags: str = "") -> bool:
        """Add encrypted password entry"""
        if not self.encryption_key:
            return False
        
        try:
            data = self.load_data()
            
            password_entry = {
                'id': int(datetime.now().timestamp() * 1000),
                'title': self.crypto.encrypt_data(title, self.encryption_key),
                'username': self.crypto.encrypt_data(username, self.encryption_key),
                'password': self.crypto.encrypt_data(password, self.encryption_key),
                'url': self.crypto.encrypt_data(url, self.encryption_key),
                'category': self.crypto.encrypt_data(category, self.encryption_key),
                'tags': self.crypto.encrypt_data(tags, self.encryption_key),
                'created_at': datetime.now().isoformat()
            }
            
            data['passwords'].append(password_entry)
            self.save_data(data)
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
    
    def get_passwords(self, category: str = None) -> list:
        """Get decrypted password entries"""
        if not self.encryption_key:
            return []
        
        try:
            data = self.load_data()
            passwords = []
            
            for entry in data.get('passwords', []):
                try:
                    decrypted = {
                        'id': entry['id'],
                        'title': self.crypto.decrypt_data(entry['title'], self.encryption_key),
                        'username': self.crypto.decrypt_data(entry['username'], self.encryption_key),
                        'password': self.crypto.decrypt_data(entry['password'], self.encryption_key),
                        'url': self.crypto.decrypt_data(entry['url'], self.encryption_key),
                        'category': self.crypto.decrypt_data(entry['category'], self.encryption_key),
                        'tags': self.crypto.decrypt_data(entry['tags'], self.encryption_key),
                        'created_at': entry.get('created_at', '')
                    }
                    
                    if not category or decrypted['category'] == category:
                        passwords.append(decrypted)
                except:
                    continue  # Skip corrupted entries
            
            return passwords
        except Exception as e:
            print(f"Error getting passwords: {e}")
            return []
    
    def add_note(self, title: str, content: str, category: str = "", tags: str = "") -> bool:
        """Add encrypted note entry"""
        if not self.encryption_key:
            return False
        
        try:
            data = self.load_data()
            
            note_entry = {
                'id': int(datetime.now().timestamp() * 1000),
                'title': self.crypto.encrypt_data(title, self.encryption_key),
                'content': self.crypto.encrypt_data(content, self.encryption_key),
                'category': self.crypto.encrypt_data(category, self.encryption_key),
                'tags': self.crypto.encrypt_data(tags, self.encryption_key),
                'created_at': datetime.now().isoformat()
            }
            
            data['notes'].append(note_entry)
            self.save_data(data)
            return True
        except Exception as e:
            print(f"Error adding note: {e}")
            return False
    
    def get_notes(self, category: str = None) -> list:
        """Get decrypted note entries"""
        if not self.encryption_key:
            return []
        
        try:
            data = self.load_data()
            notes = []
            
            for entry in data.get('notes', []):
                try:
                    decrypted = {
                        'id': entry['id'],
                        'title': self.crypto.decrypt_data(entry['title'], self.encryption_key),
                        'content': self.crypto.decrypt_data(entry['content'], self.encryption_key),
                        'category': self.crypto.decrypt_data(entry['category'], self.encryption_key),
                        'tags': self.crypto.decrypt_data(entry['tags'], self.encryption_key),
                        'created_at': entry.get('created_at', '')
                    }
                    
                    if not category or decrypted['category'] == category:
                        notes.append(decrypted)
                except:
                    continue  # Skip corrupted entries
            
            return notes
        except Exception as e:
            print(f"Error getting notes: {e}")
            return []
    
    def delete_password(self, password_id: int) -> bool:
        """Delete password entry"""
        try:
            data = self.load_data()
            data['passwords'] = [p for p in data['passwords'] if p['id'] != password_id]
            self.save_data(data)
            return True
        except:
            return False
    
    def delete_note(self, note_id: int) -> bool:
        """Delete note entry"""
        try:
            data = self.load_data()
            data['notes'] = [n for n in data['notes'] if n['id'] != note_id]
            self.save_data(data)
            return True
        except:
            return False
    
    def export_data(self, export_path: str) -> bool:
        """Export encrypted data to file"""
        try:
            data = self.load_data()
            data['export_date'] = datetime.now().isoformat()
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except:
            return False