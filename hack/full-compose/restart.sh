#! /bin/sh

docker compose pull
docker compose down
docker compose up -d
docker compose logs -f pigdns
