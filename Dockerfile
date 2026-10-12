FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY operator_src operator_src
USER 10001
ENTRYPOINT ["kopf", "run", "--standalone", "--namespace", "checkmarx-system", "/app/operator_src/handlers.py"]
