FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir -r requirements.lock.txt && useradd --create-home --uid 10001 analyst
COPY engine.py defaults.json ./
COPY killchain ./killchain
USER analyst
ENTRYPOINT ["python", "/app/engine.py"]
CMD ["--help"]
