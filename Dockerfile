FROM docker.io/library/python:3.11-bullseye

WORKDIR /app
COPY ./pyproject.toml .
RUN pip install .
CMD ./main.py
