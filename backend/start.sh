#!/bin/sh

export PYTHONPATH=/app

# 1. Start Redis server in the background
echo "🚀 Starting Redis server locally..."
redis-server --daemonize yes --port 6379

# 2. Wait for Redis to start up
until redis-cli ping >/dev/null 2>&1; do
  echo "⌛ Waiting for Redis to start..."
  sleep 1
done
echo "✅ Redis is running."

# Function to start Celery worker
start_celery() {
  echo "🚀 Starting Celery task worker..."
  celery -A workers.celery_app worker -Q recon,scanner,exploit,ai,default -c 1 --loglevel=info &
  CELERY_PID=$!
}

# Function to start FastAPI
start_fastapi() {
  echo "🚀 Starting FastAPI server..."
  uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 &
  FASTAPI_PID=$!
}

# Start workers
start_celery
start_fastapi

# 3. Monitor loop (self-healing)
echo "🛡️ Starting process health monitor loop..."
while true; do
  sleep 5

  # Check Redis status
  if ! redis-cli ping >/dev/null 2>&1; then
    echo "⚠️ Redis server is down! Attempting to restart..."
    redis-server --daemonize yes --port 6379
    sleep 2
  fi

  # Check Celery status
  if ! kill -0 $CELERY_PID >/dev/null 2>&1; then
    echo "⚠️ Celery worker died! Restarting..."
    start_celery
  fi

  # Check FastAPI status
  if ! kill -0 $FASTAPI_PID >/dev/null 2>&1; then
    echo "🚨 FastAPI server died! Exiting container to trigger platform redeployment."
    exit 1
  fi
done
