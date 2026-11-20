# syntax=docker/dockerfile:1
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
# DejaVu fonts give report PDFs full Unicode coverage. Best effort: in an offline build the PDF renderer falls back to
# core fonts (Latin-1; other characters become '?') and the Reports page says so.
RUN (apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*) \
    || echo 'WARNING: fonts-dejavu-core not installed; PDF reports will use Latin-1 core fonts'
# Optional KVM/libvirt adapter: docker build --build-arg WITH_LIBVIRT=1 (adds libvirt client libs + qemu-img)
ARG WITH_LIBVIRT=0
RUN if [ "$WITH_LIBVIRT" = "1" ]; then apt-get update && apt-get install -y --no-install-recommends libvirt-dev pkg-config gcc qemu-utils \
      && rm -rf /var/lib/apt/lists/*; fi
COPY requirements.txt requirements-vm.txt requirements.lock ./
# Optional corporate/proxy CA: docker build --secret id=extra_ca,src=/path/ca.crt
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install -r requirements.txt -c requirements.lock && if [ "$WITH_LIBVIRT" = "1" ]; then pip install -r requirements-vm.txt; fi
COPY . .
RUN useradd --system --uid 10001 cyberrange && chown -R cyberrange /app \
    && install -d -m 0700 -o cyberrange /var/lib/cyber-range/storage
USER cyberrange
EXPOSE 8000
CMD ["sh", "/app/docker-entrypoint.sh"]
