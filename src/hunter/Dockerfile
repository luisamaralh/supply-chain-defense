FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip --progress-bar off && \
    pip install --no-cache-dir --progress-bar off -r requirements.txt

COPY hunter_service.py .

CMD ["uvicorn", "hunter_service:app", "--host", "0.0.0.0", "--port", "8000"]
