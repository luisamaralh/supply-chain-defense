#!/bin/bash
set -e

echo "=> Setting Kubernetes context to supply-chain-defense namespace..."
kubectl config set-context --current --namespace=supply-chain-defense

echo "=> Deploying Secrets..."
kubectl apply -f k8s/secrets-template.yaml

echo "=> Creating/Updating ConfigMap for postgres init scripts..."
kubectl create configmap postgres-init-script --from-file=db/init.sql --dry-run=client -o yaml | kubectl apply -f -

echo "=> Deploying PostgreSQL Database..."
kubectl apply -f k8s/postgres-pvc.yaml
kubectl apply -f k8s/postgres-deployment.yaml

echo "=> Deploying OSV Sync CronJob..."
kubectl apply -f k8s/osv-sync-cronjob.yaml

echo "=> Deploying Hunter Service..."
kubectl apply -f k8s/hunter-deployment.yaml

echo "=> Deploying Frontend Dashboard..."
kubectl apply -f k8s/frontend-deployment.yaml

echo "--------------------------------------------------------"
echo "Deployment applied! It may take a minute for pods to spin up."
echo "Check the status with:"
echo "  kubectl get pods -w"
echo ""
echo "Once the hunter-service pod is running, open access to the API:"
echo "  kubectl port-forward svc/hunter-service 8000:80"
echo ""
echo "And open access to the Frontend Dashboard UI in a separate terminal:"
echo "  kubectl port-forward svc/frontend 3000:80"
echo "  Open your browser to http://127.0.0.1:3000"
echo ""
echo "Then, trigger a webhook using:"
echo "  curl -X POST http://127.0.0.1:8000/webhook/malware \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"vulnerability_id\": \"GHSA-test\", \"package_name\": \"test-pkg\", \"version\": \"1.0\", \"ecosystem\": \"npm\"}'"
echo "--------------------------------------------------------"
