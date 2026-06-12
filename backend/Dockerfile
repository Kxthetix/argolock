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
    ca-certificates \
    git \
    unzip \
    wget \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Clone SQLmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /sqlmap

# Install Go tools: subfinder, nuclei, naabu, httpx
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip subfinder && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip && \
    unzip nuclei_3.2.9_linux_amd64.zip nuclei && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.2.9_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip && \
    unzip naabu_2.3.1_linux_amd64.zip naabu && \
    mv naabu /usr/local/bin/ && \
    rm naabu_2.3.1_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip && \
    unzip httpx_1.6.8_linux_amd64.zip httpx && \
    mv httpx /usr/local/bin/ && \
    rm httpx_1.6.8_linux_amd64.zip

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

# Allow Celery to run with root privileges in Docker
ENV C_FORCE_ROOT=true

EXPOSE 8000

CMD ["./start.sh"]
