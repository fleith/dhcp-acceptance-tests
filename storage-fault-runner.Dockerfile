FROM python:3.13-slim

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iproute2 -qq \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt -q

WORKDIR /app
CMD ["tail", "-f", "/dev/null"]
