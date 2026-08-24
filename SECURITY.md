# Security Policy

## Supported Versions

CyberVault is an academic and portfolio project and is not currently maintained as a production application.

| Version | Supported |
| ------- | --------- |
| Current version | Yes |
| Older versions | No |

## Reporting a Vulnerability

If you discover a potential security vulnerability in CyberVault, please report it through GitHub rather than publicly posting details about the vulnerability.

When reporting a vulnerability, please include:

- A description of the issue
- Steps to reproduce the issue
- The potential security impact
- Any relevant screenshots, logs, or supporting information

Security issues will be reviewed and addressed as appropriate for this academic and portfolio project.

## Security Considerations

CyberVault includes security controls such as:

- bcrypt password hashing
- Fernet encryption for stored account passwords
- CSRF protection
- Session management and session expiration
- Password complexity validation
- Rate limiting
- Security-related HTTP headers
- Environment-based configuration for sensitive values
- Protected database credentials

CyberVault is intended to demonstrate secure application development and cybersecurity concepts. It should not be considered a production-ready commercial password manager without additional security review, testing, threat modeling, deployment hardening, and independent security auditing.
