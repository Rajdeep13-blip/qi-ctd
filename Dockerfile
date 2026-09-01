# Quantum-Inspired Cyber Threat Detection (QI-CTD)
# Zero-dependency base image (Pure Python 3.11 Standard Library)
FROM python:3.11-slim

WORKDIR /app

# Copy codebase
COPY . /app

# Expose port
EXPOSE 8000

# Run public server
CMD ["python", "api/server.py", "8000"]
