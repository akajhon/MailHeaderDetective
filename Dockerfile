FROM python:3.10

ENV TZ=America/Sao_Paulo

RUN adduser mhd

COPY /mhd/requirements.txt ./tmp/

RUN apt-get update && apt-get install -y gcc musl-dev && \
    pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /usr/src/mhd

USER mhd

COPY mhd/ .

EXPOSE 8080

ENTRYPOINT ["python", "/usr/src/mhd/server.py", "-b", "0.0.0.0"]