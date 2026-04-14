#!/bin/bash
set -e

# ── Usage ─────────────────────────────────────────────────────────────────────
# ./run.sh              → Docker Compose mode (default, recommended for servers)
# ./run.sh --minikube   → Minikube / Kubernetes mode
# ─────────────────────────────────────────────────────────────────────────────

MODE="compose"
if [[ "$1" == "--minikube" ]]; then
    MODE="minikube"
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
ENV_FILE="$(dirname "$0")/.env"
if [ -f "$ENV_FILE" ]; then
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

    echo "=> [Docker Compose] Starting all services..."
    docker compose up -d

    echo ""
    echo "--------------------------------------------------------"
    echo "All services are up!"
    echo ""
    echo "  Dashboard : http://localhost/"
    echo "  API       : http://localhost/api/"
    echo "  Swagger   : http://localhost/api/docs"
    echo ""
    echo "Run the first OSV data sync:"
    echo "  docker compose run --rm osv-sync"
    echo ""
    echo "Check service status:"
    echo "  docker compose ps"
    echo "  docker compose logs -f"
    echo "--------------------------------------------------------"

# ══════════════════════════════════════════════════════════════════════════════
elif [[ "$MODE" == "minikube" ]]; then
# ══════════════════════════════════════════════════════════════════════════════

    echo "=> [Minikube] Setting Kubernetes context..."
    kubectl config set-context --current --namespace=supply-chain-defense

    echo "=> [Minikube] Deploying Secrets (rendered from .env)..."
    envsubst < k8s/secrets-template.yaml | kubectl apply -f -

    echo "=> [Minikube] Creating ConfigMap for postgres init scripts..."
    kubectl create configmap postgres-init-script --from-file=db/init.sql --dry-run=client -o yaml | kubectl apply -f -

    echo "=> [Minikube] Deploying PostgreSQL..."
    kubectl apply -f k8s/postgres-pvc.yaml
    kubectl apply -f k8s/postgres-deployment.yaml

    echo "=> [Minikube] Deploying OSV Sync CronJob..."
    kubectl apply -f k8s/osv-sync-cronjob.yaml

    echo "=> [Minikube] Deploying Hunter Service..."
    kubectl apply -f k8s/hunter-deployment.yaml

    echo "=> [Minikube] Deploying Frontend..."
    kubectl apply -f k8s/frontend-deployment.yaml

    echo ""
    echo "--------------------------------------------------------"
    echo "Deployment applied! Wait for pods to be Ready:"
    echo "  kubectl get pods -w"
    echo ""
    echo "Then open port-forwards in two terminals:"
    echo "  kubectl port-forward svc/hunter-service 8000:8000"
    echo "  kubectl port-forward svc/frontend 3000:80"
    echo ""
    echo "  Dashboard : http://127.0.0.1:3000"
    echo "  Swagger   : http://127.0.0.1:8000/docs"
    echo ""
    echo "Trigger a test webhook:"
    echo "  curl -X POST http://127.0.0.1:8000/webhook/malware \\"
    echo "       -H 'Content-Type: application/json' \\"
    echo "       -d '{\"vulnerability_id\": \"MAL-test\", \"package_name\": \"test-pkg\", \"version\": \"1.0\", \"ecosystem\": \"npm\"}'"
    echo "--------------------------------------------------------"

fi
