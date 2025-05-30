FROM python:3.10-slim-buster

RUN apt-get update && apt-get install -y curl nano rsync

COPY . /app/

RUN pip install -r /app/requirements.txt

WORKDIR /app/