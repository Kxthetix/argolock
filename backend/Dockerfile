FROM python:3.12-slim

# Install system dependencies for WeasyPrint, tool runners, and Redis server
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libssl-dev \
    fonts-liberation \
    redis-server \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create reports directory
RUN mkdir -p /tmp/argolock_reports

# Make start script executable
RUN chmod +x start.sh

EXPOSE 8000

CMD ["./start.sh"]
