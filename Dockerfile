FROM python:3.9-alpine

RUN adduser -D mhd

COPY requirements.txt ./tmp/
RUN apk add --no-cache gcc musl-dev && \
    pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /usr/src/mhd

USER mhd

COPY mhd/ .

EXPOSE 8080

ENTRYPOINT ["python", "/usr/src/mhd/server.py", "-b", "0.0.0.0"]
