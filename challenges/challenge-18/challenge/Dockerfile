FROM python:alpine
RUN apk add --no-cache socat
RUN pip install --no-cache-dir pycryptodome

COPY final.py /
COPY FLAG.py /
CMD socat tcp-listen:31337,reuseaddr,fork exec:'/usr/local/bin/python final.py'
