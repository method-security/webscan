# Dockerfile used as distribution for the webscan CLI in Tool container format
FROM chromedp/headless-shell:129.0.6643.2 

ARG CLI_NAME="webscan"
ARG TARGETARCH

RUN apt-get update && apt-get install -y ca-certificates git

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/ && \
  mkdir -p /opt/method/${CLI_NAME}/var/data && \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/discover && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/discover/application && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/discover/route && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/discover/saas && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/discover/saas/bruteforce && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/enumerate && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/enumerate/cms && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/enumerate/cms/wordpress && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/pentest && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf/pentest/route && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output

COPY configs/*                                    /opt/method/${CLI_NAME}/var/conf/
COPY configs/discover/*                           /opt/method/${CLI_NAME}/var/conf/discover/
COPY configs/discover/application/*               /opt/method/${CLI_NAME}/var/conf/discover/application/
COPY configs/discover/saas/*                      /opt/method/${CLI_NAME}/var/conf/discover/saas/
COPY configs/discover/saas/bruteforce/*           /opt/method/${CLI_NAME}/var/conf/discover/saas/bruteforce/
COPY configs/enumerate/*                          /opt/method/${CLI_NAME}/var/conf/enumerate/
COPY configs/enumerate/cms/*                      /opt/method/${CLI_NAME}/var/conf/enumerate/cms/
COPY configs/enumerate/cms/wordpress/*            /opt/method/${CLI_NAME}/var/conf/enumerate/cms/wordpress/
COPY configs/pentest/*                            /opt/method/${CLI_NAME}/var/conf/pentest/
COPY configs/pentest/route/*                      /opt/method/${CLI_NAME}/var/conf/pentest/route/

COPY ${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output

USER method

WORKDIR /opt/method/${CLI_NAME}/

ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
ENTRYPOINT [ "webscan" ]