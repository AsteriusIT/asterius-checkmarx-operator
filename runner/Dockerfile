# Run python3 api-mock/scripts/download-cli.py --output-dir runner first.
# Pin the base image digest in production.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY cx /usr/local/bin/cx
RUN chmod 0555 /usr/local/bin/cx
COPY legal/ /usr/share/licenses/checkmarx-cli/
ENV HOME=/tmp USER=cx
WORKDIR /tmp
USER 10001
ENTRYPOINT ["cx"]
