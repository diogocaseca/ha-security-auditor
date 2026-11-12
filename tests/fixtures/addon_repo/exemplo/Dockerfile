ARG BUILD_FROM
FROM ${BUILD_FROM}
ADD https://example.com/ferramenta.tgz /tmp/
RUN curl -fsSL https://get.example.com/install.sh | sh
COPY rootfs /
