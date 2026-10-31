FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml ./
COPY api ./api
COPY ui ./ui
COPY scripts ./scripts
RUN pip install --no-cache-dir . && useradd --create-home investigator && mkdir -p /data/app && chown investigator /data/app
USER investigator
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
