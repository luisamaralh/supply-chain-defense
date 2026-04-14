#!/bin/bash
set -e

# ── Usage ─────────────────────────────────────────────────────────────────────
# ./setup.sh            → Docker Compose mode (default, recommended for servers)
# ./setup.sh --minikube → Minikube mode (local Kubernetes development)
# ─────────────────────────────────────────────────────────────────────────────

MODE="compose"
if [[ "$1" == "--minikube" ]]; then
    MODE="minikube"
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="$(dirname "$0")/.env"
if [ -f "$ENV_FILE" ]; then
    echo "=> Loading environment from .env..."
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "ERROR: .env file not found."
    echo "       Copy .env.example to .env and fill in your secrets."
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "compose" ]]; then
# ══════════════════════════════════════════════════════════════════════════════

    echo "=> [Docker Compose] Building all images..."
    docker compose build --no-cache

    echo "--------------------------------------------------------"
    echo "Build complete! Run './run.sh' to start all services."
    echo "Or run './run.sh --compose' explicitly."
    echo "--------------------------------------------------------"

# ══════════════════════════════════════════════════════════════════════════════
elif [[ "$MODE" == "minikube" ]]; then
# ══════════════════════════════════════════════════════════════════════════════

    echo "=> [Minikube] Checking if minikube is installed..."
    if ! command -v minikube &> /dev/null; then
        echo "ERROR: minikube is not installed."
        echo "       Install with: brew install minikube"
        exit 1
    fi

    echo "=> [Minikube] Starting cluster..."
    minikube start --driver=docker

    echo "=> [Minikube] Creating supply-chain-defense namespace..."
    kubectl create namespace supply-chain-defense --dry-run=client -o yaml | kubectl apply -f -
    kubectl config set-context --current --namespace=supply-chain-defense

    echo "=> [Minikube] Pointing Docker CLI at Minikube's daemon..."
    eval "$(minikube -p minikube docker-env 2>/dev/null | grep '^export ')"

    echo "=> [Minikube] Building osv-sync image..."
    docker build -t osv-sync:latest src/sync/

    echo "=> [Minikube] Building hunter-service image..."
    docker build -t hunter-service:latest src/hunter/

    echo "=> [Minikube] Building frontend image..."
    docker build -t frontend-service:latest src/frontend/

    echo "--------------------------------------------------------"
    echo "Build complete! Run './run.sh --minikube' to deploy."
    echo "--------------------------------------------------------"

fi
