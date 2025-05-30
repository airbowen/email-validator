# email-validator

## High-Level Architecture

```
┌─────────┐     ┌──────────┐         ┌─────────────────┐
│         │     │          │         │                 │
│ Users   ├────►│  Nginx   ├────┬───►│  Redis Cache    │
│         │     │          │    │    │                 │
└─────────┘     └──────────┘    │    └─────────────────┘
                                │
                                │    ┌─────────────────┐
                                │    │                 │
                                ├───►│  API Service    │
                                │    │  (Golang)       │
                                │    └────────┬────────┘
                                │             │
                                │             ▼
                                │    ┌─────────────────┐
                                │    │                 │
                                └───►│  PostgreSQL DB  │
                                     │                 │
                                     └─────────────────┘
```

## How to start

### Prerequisites
- Install Docker Compose or Docker Desktop

### Using Docker to start
Starting:
```
$ docker-compose up --build
```

Stopping:
```
$ docker-compose down
```

### Generate the server.crt and server.key
```
$ openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt
```

## Security Risks and Mitigation Plans
### Current Security Risks

### 1. Email Storage and Privacy

Risk: Storing email addresses in a database creates a privacy risk, even when hashed. The bcrypt hashing in our solution helps, but isn't perfect for this use case.

### Mitigation:

Use stronger specialized key derivation functions specifically designed for this purpose
Implement data minimization by purging older check records periodically
Consider tokenization instead of storing actual hashed emails

### 2. API Rate Limiting Bypass
Risk: While we implemented rate limiting in Nginx, sophisticated attackers could distribute requests across multiple IP addresses to bypass this defense.

### Mitigation:

Implement application-level rate limiting by user/session
Add CAPTCHA for suspicious activity patterns
Consider commercial anti-bot solutions for more sophisticated protection

### 3. Cache Poisoning
Risk: Our Redis cache could potentially be compromised if the application logic has flaws.

### Mitigation:

Implement cache entry validation when retrieving data
Set appropriate TTL values for cache entries
Add integrity checks for cached data

### 4. SSL/TLS Configuration
Risk: Self-signed certificates are used in the current setup, which creates trust issues and can be vulnerable to man-in-the-middle attacks.

### Mitigation:

Deploy proper CA-signed certificates in production
Implement certificate pinning
Enable HSTS with appropriate age values

### 5. Container Security
Risk: The Docker containers may have unnecessary privileges or vulnerabilities in base images.

### Mitigation:

Use security scanning tools like Trivy or Clair
Implement least privilege principles for containers
Keep base images updated and use minimal images when possible

### 6. Dependency Vulnerabilities
Risk: The application relies on multiple external packages that may contain security vulnerabilities.

### Mitigation:

Regular dependency scanning and updates
Implement a software composition analysis (SCA) tool in the CI/CD pipeline
Vendor dependencies where appropriate to control update timing