FROM python:3.12-slim@sha256:f3fa41d74a768c2fce8016b98c191ae8c1bacd8f1152870a3f9f87d350920b7c

# Keep OS packages patched so Trivy does not fail on fixed CVEs baked into the base image.
RUN apt-get update \
  && apt-get upgrade -y \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/app

# Install locked dependencies with hashes.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock.txt

# Copy app source (run from source, do not pip-install the project).
COPY ghostmcp /app/ghostmcp

# The remote gateway defaults to GHOSTMCP_HTTP_PORT=8000.
EXPOSE 8000

ENTRYPOINT ["python", "-m", "ghostmcp"]
