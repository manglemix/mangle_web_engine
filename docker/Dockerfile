FROM ubuntu:latest

COPY mangle_web_engine /mangle_web_engine
COPY Rocket.toml /Rocket.toml

COPY bashrc_append /bashrc_append
RUN ["/bin/bash", "-c", "cat /bashrc_append >> /root/.bashrc && rm /bashrc_append"]

RUN apt update && apt install git nano -y

# RUN apt update -y && \
#     apt upgrade -y && \
#     apt install snapd -y && \
#     snap install core && \
#     snap refresh core && \
#     snap install --classic certbot && \
#     ln -s /snap/bin/certbot /usr/bin/certbot