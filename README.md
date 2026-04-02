# Supply Chain Defense Pipeline

This repository contains the logic and infrastructure manifests for a supply chain attack defense system, powered by OSV (Open Source Vulnerabilities) data and hunting integrations via JFrog Artifactory and CrowdStrike Falcon.

## Project Structure

- `db/`: Contains the initialization SQL for the PostgreSQL database which stores OSV records using `JSONB`.
- `k8s/`: Contains the Openshift/Kubernetes manifests for deploying the system.
- `src/sync/`: Python CronJob application that runs hourly, downloading all vulnerability history from `gs://osv-vulnerabilities/all.zip` and pushing it to the PostgreSQL DB.
- `src/hunter/`: FastAPI service designed to receive threat intelligence alerts (triggering searches in JFrog Artifactory and CrowdStrike) and serve vulnerability data out to the Frontend.
- `src/frontend/`: React + Vite Frontend application providing an aesthetic dashboard for OSINT data, featuring dynamic JSONB filtering and pagination.

## Getting Started Locally (Minikube)

We have provided automated scripts to help you deploy the system on a local Minikube cluster.

### 1. Configure Secrets
Before deploying, edit the `k8s/secrets-template.yaml` file to include your actual API tokens and passwords for Artifactory and Falcon.

### 2. Initialization and Building
Ensure you have Minikube installed (e.g. `brew install minikube`). 
Run the setup script which will automatically start Minikube, configure the namespaces, and build the Docker images for the pipeline directly in the cluster's environment:
```bash
./setup.sh
```

### 3. Deploy Infrastructure
Once the setup is complete, you can deploy the PostgreSQL database, the `osv-sync` CronJob, the `hunter` REST/Webhook service, and the `frontend` Dashboard Application using the run script:
```bash
./run.sh
```

### 4. Access the Frontend Dashboard
To interact with the OSINT data via the rich browser dashboard, use `kubectl port-forward` to map the services to your local machine:
```bash
# Terminal 1 - The Backend API
kubectl port-forward svc/hunter-service 8000:80

# Terminal 2 - The Frontend React UI
kubectl port-forward svc/frontend 3000:80
```
Then navigate to `http://127.0.0.1:3000` in your web browser!

### 5. Triggering the Hunter Service
You can mock an alert by port-forwarding the `hunter-service` Service and sending a cURL POST request:
```bash
kubectl port-forward svc/hunter-service 8000:80

curl -X POST http://127.0.0.1:8000/webhook/malware \
     -H "Content-Type: application/json" \
     -d '{"vulnerability_id": "GHSA-1234", "package_name": "log4j", "version": "2.14.0", "ecosystem": "Maven"}'
```
You can view the logs to see the Artifactory and CrowdStrike hunting processes running:
```bash
kubectl logs -f deployment/hunter-service
```

### 6. Interactive API Documentation (Swagger UI)
Because the `hunter-service` is built with FastAPI, comprehensive interactive Swagger documentation is generated automatically out of the box. 
Once you have port-forwarded `svc/hunter-service 8000:80` as shown above, you can access the full API Schema and test the endpoints directly by navigating to:
**http://127.0.0.1:8000/docs**
