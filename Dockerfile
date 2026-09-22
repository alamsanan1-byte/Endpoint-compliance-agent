FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/app/data/compliance.db
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock \
    && groupadd --gid 10001 collector \
    && useradd --uid 10001 --gid collector --no-create-home collector
COPY collector ./collector
COPY policy ./policy
COPY schema ./schema
RUN mkdir /app/data && chown collector:collector /app/data
USER collector
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)"
CMD ["uvicorn", "collector.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
