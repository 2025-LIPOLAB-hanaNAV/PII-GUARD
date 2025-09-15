FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY pii-guard/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy PII-GUARD source code
COPY pii-guard/ .

# Create data directory
RUN mkdir -p data

# Expose port 3000
EXPOSE 3000

# Set environment variables
ENV PYTHONPATH=/app

# Start the application
CMD ["python", "-m", "pii_guard.api"]