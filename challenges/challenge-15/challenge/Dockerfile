FROM node:21-alpine

RUN apk update && apk add texmf-dist texlive-full imagemagick php82-cgi
RUN apk add gcc libc-dev

WORKDIR /
COPY app /app
COPY Dockerfile /Dockerfile
COPY actual-flag /app/actual-flag
RUN chmod +x /app/start.sh /app/setup.sh
RUN /app/setup.sh

EXPOSE 8080

ENTRYPOINT [ "/app/start.sh" ]