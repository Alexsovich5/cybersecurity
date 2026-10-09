FROM koalaman/shellcheck:v0.5.0 AS shellcheck

FROM python:3.6.6-stretch@sha256:5b2e0d981c74fa8b53db311e0c5b7672c8c3958053496f42ef29697cec3af277

COPY --from=shellcheck /bin/shellcheck /usr/local/bin/

COPY requirements-dev.txt /tmp/
RUN pip install --no-cache-dir --no-deps -r /tmp/requirements-dev.txt && pip check

ENV ANSIBLE_CONFIG=/src/ansible/ansible.cfg
WORKDIR /src
