# Dockerfile used as distribution for the webscan CLI in Tool container format
FROM chromedp/headless-shell:129.0.6643.2 

RUN ln -s /headless-shell/headless-shell /usr/bin/chrome

ARG CLI_NAME="webscan"
ARG TARGETARCH

# Clean package cache after install to save space
RUN apt-get update && \
    apt-get install -y ca-certificates git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create user first to avoid ownership changes later
RUN adduser --disabled-password --gecos '' method

# Setup Method Directory Structure with correct ownership from start
RUN mkdir -p /opt/method/${CLI_NAME}/var/data/tmp \
             /opt/method/${CLI_NAME}/var/conf \
             /opt/method/${CLI_NAME}/var/log \
             /opt/method/${CLI_NAME}/service/bin \
             /mnt/output && \
    chown -R method:method /opt/method/${CLI_NAME}/ /mnt/output

# Copy files as method user to avoid chown operations
USER method
COPY --chown=method:method configs/ /opt/method/${CLI_NAME}/var/conf/
COPY --chown=method:method ${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
ENTRYPOINT [ "webscan" ]