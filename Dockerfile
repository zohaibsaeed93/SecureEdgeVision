FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY . .

# The foundation services are stdlib-only placeholders. Later feature commits
# will install the locked runtime dependencies before starting real services.
CMD ["python", "-m", "apps.aggregator.main"]
