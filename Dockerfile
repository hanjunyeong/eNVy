FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libmagic1 ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 envy \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent envy

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt

COPY --chown=10001:10001 envy /app/envy
COPY --chown=10001:10001 static /app/static
COPY --chown=10001:10001 scripts/benchmark_cache.py /app/scripts/benchmark_cache.py

USER 10001:10001
CMD ["python", "-m", "uvicorn", "envy.api:app", "--host", "0.0.0.0", "--port", "8000"]
