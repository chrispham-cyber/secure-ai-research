# syntax=docker/dockerfile:1
# Application image for the Secure AI Research Platform.
# PUBLIC / synthetic data only. Not approved for CUI or classified information.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Pinned runtime dependencies first, for layer caching.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Then the application package (deps already satisfied above).
COPY pyproject.toml ./
COPY src ./src
COPY infrastructure/model-runtime/model-registry.json ./infrastructure/model-runtime/model-registry.json
RUN pip install --no-deps .

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000
CMD ["uvicorn", "secure_ai_research.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
