#!/bin/bash
set -e

echo "=> Checking if minikube is installed..."
if ! command -v minikube &> /dev/null; then
    echo "ERROR: minikube is not installed."
    echo "You can install it using Homebrew on macOS: 'brew install minikube'"
    exit 1
fi

echo "=> Starting minikube (this may take a minute)..."
# Setting --driver=docker as it works best on Apple Silicon (M1/M2) and avoids hyperkit errors
minikube start --driver=docker

echo "=> Creating supply-chain-defense namespace..."
kubectl create namespace supply-chain-defense --dry-run=client -o yaml | kubectl apply -f -
kubectl config set-context --current --namespace=supply-chain-defense

echo "=> Configuring Docker environment to use Minikube's daemon..."
eval "$(minikube -p minikube docker-env 2>/dev/null | grep '^export ')"

echo "=> Building Sync Application image locally..."
cd src/sync
docker build -t osv-sync:latest .
# Build Hunter App
echo "=> Building Hunter Application image locally..."
cd ../hunter
docker build -t hunter-service:latest .

# Build Frontend App
echo "=> Building Frontend Application image locally..."
cd ../frontend
docker build -t frontend-service:latest .
cd ../../

echo "--------------------------------------------------------"
echo "Setup is mostly complete! However, before deploying,"
echo "make sure to update 'k8s/secrets-template.yaml' with"
echo "your actual API keys and tokens for Artifactory and Falcon."
echo "--------------------------------------------------------"
echo "When you're ready, execute './run.sh' to deploy everything."
