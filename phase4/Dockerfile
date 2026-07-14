# We use a minimal Python image — nothing extra installed
# that could mask or interfere with what the package does
FROM python:3.11-slim

# Install strace — this is the tool that watches every
# system call the package makes (network, file, process)
RUN apt-get update && apt-get install -y \
    strace \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user — safer, closer to real CI environments
RUN useradd -m -u 1000 scanner
USER scanner
WORKDIR /home/scanner

# Copy the monitoring script into the container
COPY --chown=scanner:scanner monitor.py .

# This will be overridden at runtime with the actual package name
CMD ["python", "monitor.py", "requests"]