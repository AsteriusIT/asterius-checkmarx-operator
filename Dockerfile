FROM python:3.15.0-alpine3.24
# Apply security updates that landed after the base image was published.
RUN apk upgrade --no-cache
WORKDIR /app
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/checkmarx-operator/
COPY requirements.lock requirements-build.txt ./
# Package management is only needed during the build, not by the operator.
RUN python -m pip install --no-cache-dir --no-compile --require-hashes \
        --only-binary=:all: --no-binary=pyyaml \
        --build-constraint requirements-build.txt -r requirements.lock \
    && python -m pip check \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.15/ensurepip
COPY operator_src operator_src
RUN adduser -D -u 10001 checkmarx
USER 10001
ENTRYPOINT ["kopf", "run", "--standalone", "--namespace", "checkmarx-operator", "/app/operator_src/handlers.py"]
