#!/usr/bin/env fish

# Variablen
set USER casparjones
set IMAGE rclone
set TAG v0.1.0
set FULLNAME "$USER/$IMAGE:$TAG"

echo "👉 Baue Docker Image: $FULLNAME"

# 1. Login (nur nötig, wenn du noch nicht eingeloggt bist)
docker login

# 2. Build
docker build -t $FULLNAME .

# 3. Optional: zusätzlich latest setzen
docker tag $FULLNAME $USER/$IMAGE:latest

# 4. Push beide Tags
docker push $FULLNAME
docker push $USER/$IMAGE:latest