FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY operator_src operator_src
RUN useradd --uid 10001 --create-home checkmarx
USER 10001
ENTRYPOINT ["kopf", "run", "--standalone", "--namespace", "checkmarx-operator", "/app/operator_src/handlers.py"]
