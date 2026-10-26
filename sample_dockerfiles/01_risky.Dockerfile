# Sample only. A badly written Dockerfile.
FROM ubuntu:latest
ENV DB_PASSWORD=hunter2
ENV APP_ENV=production
ADD https://example.test/app.tar.gz /opt/app.tar.gz
ADD config.ini /etc/app/config.ini
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.test/install.sh | sh
RUN chmod -R 777 /opt/app
EXPOSE 22 8080
USER root
CMD ["/opt/app/start"]
