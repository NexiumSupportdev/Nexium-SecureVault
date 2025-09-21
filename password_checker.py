import re
import secrets
import string

class PasswordChecker:
    def __init__(self):
        self.common_passwords = {'password', '123456', 'qwerty', 'admin'}
    
    def check_strength(self, password: str) -> dict:
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Use at least 8 characters")
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 15
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'\d', password):
            score += 15
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            feedback.append("Add special characters")
        
        # Common password check
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("Avoid common passwords")
        
        # Determine strength
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Medium"
        else:
            strength = "Weak"
        
        return {
            'score': max(0, score),
            'strength': strength,
            'feedback': feedback
        }
    
    def generate_password(self, length: int = 16) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(length))