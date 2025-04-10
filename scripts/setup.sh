#!/bin/bash

# Generate self-signed certificate if not exists
if [ ! -f "../nginx/certs/server.crt" ]; then
  echo "Generating self-signed SSL certificate..."
  mkdir -p ../nginx/certs
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ../nginx/certs/server.key \
    -out ../nginx/certs/server.crt \
    -subj "/CN=localhost"
fi

# Build and start the containers
cd ..
docker-compose up -d

echo "System is starting up! It may take a moment..."
echo "Access the application at https://localhost"