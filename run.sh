#!/bin/sh

terraform init -backend-config="conn_str=$POSTGRES_CONNECTION_STRING"

python3 main.py > arguments.json
cat arguments.json

terraform apply -var-file arguments.json -auto-approve
