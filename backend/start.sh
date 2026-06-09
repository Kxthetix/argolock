#!/bin/sh

# 1. Start Redis server in the background
echo "🚀 Starting Redis server locally..."
redis-server --daemonize yes --port 6379

# 2. Wait for Redis to start up
until redis-cli ping >/dev/null 2>&1; do
  echo "⌛ Waiting for Redis to start..."
  sleep 1
done
echo "✅ Redis is running."

# 3. Start Celery worker in the background
echo "🚀 Starting Celery task worker..."
celery -A workers.celery_app worker -c 1 --loglevel=info &

# 4. Start FastAPI application in the foreground (binds to the port Render provides)
echo "🚀 Starting FastAPI server..."
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
