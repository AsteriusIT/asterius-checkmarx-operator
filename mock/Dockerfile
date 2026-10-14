FROM busybox:1.37.0
COPY cx /usr/local/bin/cx
RUN chmod 0555 /usr/local/bin/cx
USER 10001
ENTRYPOINT ["cx"]
