FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip --progress-bar off && \
    pip install --no-cache-dir --progress-bar off -r requirements.txt

COPY sync_osv.py .

CMD ["python", "sync_osv.py"]
