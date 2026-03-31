# syntax=docker/dockerfile:1

FROM ubuntu:22.04

USER root

ARG DEBIAN_FRONTEND=noninteractive
ARG NSO_VERSION=6.6
ARG NSO_INSTALLER=

ENV NSO_VERSION=${NSO_VERSION} \
    NSO_HOME=/root/nso-${NSO_VERSION} \
    EXTRA_NEDS_DIR=/opt/nso-extra-neds

LABEL maintainer="Muhammad Rafi" \
    image.authors="murafi@cisco.com" \
    image.version="${NSO_VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ant \
        build-essential \
        ca-certificates \
        libexpat1 \
        libxml2 \
        libxml2-utils \
        net-tools \
        openssh-client \
        openssl \
        openjdk-17-jdk \
        python3 \
        python3-dev \
        python3-pip \
        xsltproc \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && pip3 install --upgrade pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY . /tmp/build-context

RUN installer_path="${NSO_INSTALLER}" \
    && if [ -z "${installer_path}" ]; then \
        installer_path="$(find /tmp/build-context -maxdepth 2 -type f -name 'nso-*.linux.x86_64.installer.bin' | sort | head -n 1)"; \
    fi \
    && if [ -z "${installer_path}" ] || [ ! -f "${installer_path}" ]; then \
        echo "Cisco NSO installer.bin not found in the repository root. Run 'make prepare' or pass --build-arg NSO_INSTALLER=<path>." >&2; \
        exit 1; \
    fi \
    && cp "${installer_path}" /root/nso-installer.bin \
    && mkdir -p "$HOME/.ssh" \
    && ssh-keygen -t rsa -C "$HOSTNAME" -f "$HOME/.ssh/id_rsa" -P "" \
    && sh /root/nso-installer.bin --local-install "${NSO_HOME}" \
    && rm -f /root/nso-installer.bin \
    && echo "source ${NSO_HOME}/ncsrc" >> /root/.bashrc

SHELL ["/bin/bash", "-lc"]

RUN mkdir -p "${EXTRA_NEDS_DIR}/tarballs" "${EXTRA_NEDS_DIR}/seen" \
    && while IFS= read -r -d '' tgz; do \
        base="$(basename "$tgz")"; \
        if [ -e "${EXTRA_NEDS_DIR}/seen/${base}" ]; then \
            continue; \
        fi; \
        cp "$tgz" "${EXTRA_NEDS_DIR}/tarballs/${base}"; \
        tar -xzf "$tgz" -C "${EXTRA_NEDS_DIR}"; \
        touch "${EXTRA_NEDS_DIR}/seen/${base}"; \
    done < <(find /tmp/build-context -maxdepth 2 -type f -name 'ncs-*.tar.gz' -print0 | sort -z) \
    && while IFS= read -r -d '' nested_tgz; do \
        tar -xzf "$nested_tgz" -C "${EXTRA_NEDS_DIR}"; \
    done < <(find "${EXTRA_NEDS_DIR}" -mindepth 2 -type f -name 'ncs-*.tar.gz' -print0 | sort -z) \
    && while IFS= read -r req; do \
        pip3 install --no-cache-dir -r "$req"; \
    done < <(find "${EXTRA_NEDS_DIR}" -type f -name 'requirements.txt' | sort) \
    && rm -rf "${EXTRA_NEDS_DIR}/seen" /tmp/build-context

COPY entrypoint.sh /root/entrypoint.sh
RUN chmod +x /root/entrypoint.sh

EXPOSE 2022 2024 8080 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD bash -lc 'source "${NSO_HOME}/ncsrc" && test -f /root/ncs-instance/ncs.conf && cd /root/ncs-instance && ncs --status >/dev/null 2>&1'

ENTRYPOINT ["/root/entrypoint.sh"]
