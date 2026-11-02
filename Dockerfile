# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    anonsurf \
    nikto \
    curl \
    wget \
    dnsutils \
    whois \
    xmlstarlet \
    xsltproc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p ~/.hazarus/{state,audit_logs,authorization,reports,evidence,logs,config}

# Set permissions
RUN chmod 755 ~/.hazarus

# Install HAZARUS
RUN pip install -e .

# Expose dashboard port
EXPOSE 8000

# Default command
CMD ["hazarus", "--help"]
