# Build with .cache as context after scripts/download-cli.py verifies the binary.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY cx /usr/local/bin/cx
COPY legal/ /usr/share/licenses/checkmarx-cli/
RUN chmod 0555 /usr/local/bin/cx
ENV HOME=/tmp USER=cx
WORKDIR /tmp
USER 10001
ENTRYPOINT ["cx"]
