# SPDX-FileCopyrightText: Magenta ApS
#
# SPDX-License-Identifier: MPL-2.0
FROM hashicorp/terraform:1.3.8

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apk add python3 py3-pip
RUN pip install --no-cache-dir click pydantic[email]

WORKDIR /app
COPY main.py .
COPY keycloak.tf .
COPY .terraform.lock.hcl .
COPY run.sh .
ENTRYPOINT [ "sh", "run.sh" ]
