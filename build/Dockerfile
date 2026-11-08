FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome==3.21.0 \
 && useradd -m -u 1001 vault

WORKDIR /app
COPY app.py entrypoint.sh vaultcheck.c ./
COPY decoys/ /app/decoys/

RUN gcc -O2 -o /usr/local/bin/vaultcheck vaultcheck.c \
 && chown root:root /usr/local/bin/vaultcheck \
 && chmod 4755 /usr/local/bin/vaultcheck \
 && mkdir -p /var/lib/vault /opt/keys \
 && cp /app/decoys/legacy-report.chk /var/lib/vault/legacy-report.chk \
 && cp /app/decoys/sweep-2026-10.chk /var/lib/vault/sweep-2026-10.chk \
 && cp /app/decoys/notes.txt /home/vault/notes.txt \
 && chmod 755 /app/entrypoint.sh \
 && chmod 644 /var/lib/vault/*.chk /home/vault/notes.txt \
 && chown -R vault:vault /var/lib/vault /opt/keys /home/vault

USER vault
EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
