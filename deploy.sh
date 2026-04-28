#!/bin/bash

# Create necessary directories
mkdir -p nginx detector/data detector/logs

# Check if config.yaml exists
if [ ! -f detector/config.yaml ]; then
    echo "Error: detector/config.yaml not found!"
    exit 1
fi

# Check if nginx config exists
if [ ! -f nginx/nginx.conf ]; then
    echo "Error: nginx/nginx.conf not found!"
    exit 1
fi

# Pull latest images
docker-compose pull

# Stop and remove old containers
docker-compose down

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs --tail=50 detector
