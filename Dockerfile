FROM python:3.11-slim

WORKDIR /app

# System dependencies for lxml, sentence-transformers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl libxml2-dev libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY config/ ./config/
COPY src/ ./src/
COPY run_api.py .

# Data dirs (mounted as volumes in production)
RUN mkdir -p data/input data/output data/cache data/logs \
    data/rag_corpus/nvd_advisories data/rag_corpus/cisa_kev_notes \
    data/rag_corpus/vendor_advisories data/uploads

ENV PYTHONPATH=/app/src
ENV APP_ENV=prod

EXPOSE 8000

CMD ["python", "run_api.py"]
