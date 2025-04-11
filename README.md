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