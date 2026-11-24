# Dockerfile for Threat Intelligence AI Application
# Course: 23CSE528 - NoSQL Databases using MongoDB (Exercise 13 & Appendix A.6)

FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose backend API and frontend Streamlit ports
EXPOSE 8000 8501

# Health check (Exercise 14)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Default command launches backend
CMD ["uvicorn", "threat_intel_api:app", "--host", "0.0.0.0", "--port", "8000"]
