# Obtain an official Linux cx release, verify its published checksum, and place
# the executable beside this Dockerfile. Pin the base image digest in production.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --chmod=0555 cx /usr/local/bin/cx
ENV HOME=/tmp
WORKDIR /tmp
USER 10001
ENTRYPOINT ["cx"]
