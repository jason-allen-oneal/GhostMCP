FROM python:3.12-slim@sha256:a922320ae2598dfbb2f1db10aaebf3ac32f2245bdc439f0c1017234bfc01104d

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/app

# Install locked dependencies with hashes.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock.txt

# Copy app source (run from source, do not pip-install the project).
COPY ghostmcp /app/ghostmcp

EXPOSE 8766

ENTRYPOINT ["python", "-m", "ghostmcp"]
