# Dockerfile used as distribution for the webscan CLI in Tool container format
FROM chromedp/headless-shell:129.0.6643.2 

RUN ln -s /headless-shell/headless-shell /usr/bin/chrome

ARG CLI_NAME="webscan"
ARG TARGETARCH

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output

COPY configs/                                 /opt/method/${CLI_NAME}/var/conf/

COPY ${CLI_NAME}                              /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
ENTRYPOINT [ "webscan" ]