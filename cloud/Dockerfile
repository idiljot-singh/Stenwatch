# Build from the repo root:  docker build -f cloud/Dockerfile -t stenwatch-demo .
# cve.db (not in git) is baked in so the demo ranks offline; organisation files are not (see Dockerfile.dockerignore).
FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY . .
RUN useradd -r -u 10001 stenwatch && chown -R stenwatch /app
USER stenwatch
ENV HOST=0.0.0.0 PORT=8000 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python", "cloud/serve.py"]
