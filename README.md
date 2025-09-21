# Nexium SecureVault

A comprehensive all-in-one security application combining password strength checking, password management, and secure note storage with enterprise-grade encryption.

## Features

### 🔍 Password Strength Checker
- Real-time password analysis
- Strength scoring (0-100)
- Detailed feedback and suggestions
- Automatic strong password generation
- Common password detection

### 🔐 Password Manager
- AES-256-GCM encryption
- Secure password storage
- Category organization
- Search and filter capabilities
- Auto-fill integration ready

### 📝 Secure Notes
- Encrypted note storage
- Category and tag organization
- Rich text support
- Search functionality
- Export/import capabilities

## Security Features

### Encryption
- **AES-256-GCM**: Authenticated encryption for data
- **PBKDF2**: Key derivation with 100,000 iterations
- **Secure random salt generation**
- **HMAC verification** for data integrity

### Authentication
- Master password protection
- Rate limiting (3 attempts, 5-minute lockout)
- Session timeout (30 minutes)
- Optional biometric authentication
- Two-factor authentication support

### Data Protection
- Local storage only (no cloud dependency)
- Secure memory handling
- Audit logging
- Backup and recovery options

## Installation

### Python Desktop Version

1. Install Python 3.8+
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Run the application:
```bash
python nexium_gui.py
```

### Web Version

1. Open `index.html` in a modern web browser
2. No additional installation required
3. Works offline with local storage

## Usage

### First Time Setup
1. Launch the application
2. Create a strong master password
3. Optionally enable two-factor authentication
4. Start adding passwords and notes

### Password Management
- Click "Password Manager" tab
- Fill in the form with site details
- Use the password generator for strong passwords
- Save and organize with categories

### Secure Notes
- Click "Secure Notes" tab
- Create titled notes with rich content
- Organize with categories and tags
- All content is automatically encrypted

## Security Best Practices

### Master Password
- Use at least 12 characters
- Include uppercase, lowercase, numbers, and symbols
- Avoid common words or patterns
- Don't reuse from other services

### Data Backup
- Regularly export encrypted backups
- Store backups in secure locations
- Test recovery procedures
- Keep backup codes for 2FA

### System Security
- Keep your OS updated
- Use antivirus software
- Enable firewall protection
- Regular security scans

## Technical Architecture

### Encryption Flow
```
User Data → PBKDF2 Key Derivation → AES-256-GCM Encryption → Secure Storage
```

### Data Storage
- **Desktop**: SQLite database with encrypted fields
- **Web**: Browser localStorage with encrypted data
- **Backup**: Encrypted JSON export format

### Key Management
- Master password never stored in plain text
- Keys derived on-demand from master password
- Automatic key rotation capabilities
- Secure key deletion on logout

## Development

### Project Structure
```
nexium-project/
├── crypto_manager.py      # Core encryption functions
├── password_checker.py    # Password analysis
├── data_manager.py        # Database operations
├── nexium_gui.py         # Desktop GUI
├── security_features.py   # Advanced security
├── index.html            # Web interface
├── styles.css            # Web styling
├── app.js               # Web application logic
├── crypto-manager.js     # Web encryption
└── requirements.txt      # Python dependencies
```

### Adding Features
1. Fork the repository
2. Create feature branch
3. Implement with security review
4. Add tests and documentation
5. Submit pull request

## Security Considerations

### Threat Model
- **Local attacks**: Malware, physical access
- **Data breaches**: Database compromise
- **Password attacks**: Brute force, dictionary
- **Social engineering**: Phishing, pretexting

### Mitigations
- Strong encryption at rest
- Rate limiting and lockouts
- Secure coding practices
- Regular security audits
- User education and warnings

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, feature requests, or security reports:
- Email: Coming Soon
- Support https://discord.gg/zcNRGBMS83

## Changelog

### v1.0.0 (Initial Release)
- Password strength checker
- Basic password manager
- Secure notes functionality
- AES-256 encryption
- Desktop and web versions

### Planned Features
- Mobile applications
- Browser extensions
- Cloud sync (optional)
- Advanced 2FA methods
- Enterprise features

