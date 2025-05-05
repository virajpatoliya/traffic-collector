FROM python:3.10-slim

WORKDIR /app

# Copy files first
COPY . .

# Install dependencies
RUN apt-get update && \
    apt-get install -y tcpdump libpcap-dev && \
    pip install --no-cache-dir -r requirements.txt

CMD ["python", "collector.py"]
