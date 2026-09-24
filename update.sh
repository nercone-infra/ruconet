#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "> Pull"

sudo git pull

echo
echo "> Start"

docker compose pull
docker compose up -d
