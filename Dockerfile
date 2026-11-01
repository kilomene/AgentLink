FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY agentlink ./agentlink
RUN pip install --no-cache-dir .
RUN mkdir -p /data
EXPOSE 8765
CMD ["agentlink", "relay", "--host", "0.0.0.0", "--port", "8765", "--db", "/data/relay.db"]
