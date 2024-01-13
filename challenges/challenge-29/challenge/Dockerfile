FROM python:latest

WORKDIR /service

COPY ./server.py /service
COPY ./requirements.txt /service

RUN pip install -r ./requirements.txt

CMD ["python", "./server.py"]

