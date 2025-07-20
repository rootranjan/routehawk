# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in RouteHawk, please report it privately:

1. **Email**: rootranjan+routehawk@gmail.com
2. **Subject**: "[SECURITY] RouteHawk Vulnerability Report"
3. **Include**: 
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Security Best Practices

### For Users

1. **Environment Variables**: Store sensitive configuration in environment variables
2. **File Permissions**: Ensure scan directories have appropriate permissions
3. **Network Security**: Use HTTPS when running web interface
4. **Regular Updates**: Keep RouteHawk updated to latest version

### For Contributors

1. **Input Validation**: Always validate user inputs
2. **Path Traversal**: Use secure path resolution for file operations
3. **Command Injection**: Sanitize inputs before subprocess calls
4. **Secrets**: Never commit secrets or credentials
5. **Dependencies**: Keep dependencies updated

## Security Features

- ✅ Input validation and sanitization
- ✅ Path traversal protection
- ✅ Command injection prevention
- ✅ Secure temporary file handling
- ✅ No sensitive data in logs
- ✅ AGPL-3.0 license protection

## Vulnerability Disclosure Timeline

- **Day 0**: Vulnerability reported
- **Day 1-3**: Initial assessment and acknowledgment
- **Day 4-14**: Investigation and fix development
- **Day 15-30**: Testing and release preparation
- **Day 31**: Public disclosure and patch release

