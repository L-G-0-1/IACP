# Start from an official lightweight Python 3.12 image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Install a few system packages we might need
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file if it exists (the * makes it optional)
COPY requirements.txt* ./

# Install Python packages.
# "|| true" means: do not fail the build if the packages are missing.
RUN pip install --no-cache-dir cryptography ollama || true

# Copy the rest of the project files into the image
COPY . .

# Make Python output appear immediately in the logs
ENV PYTHONUNBUFFERED=1

# Default command (can be overridden in docker-compose)
CMD ["python", "discovery_server.py"]