FROM docker.io/library/ubuntu:22.04

WORKDIR /app

# Installation de tshark, nginx, tcpdump, curl et python3
RUN apt update && apt install -y tshark nginx tcpdump curl python3

ADD ./payload.sh /app/payload.sh
RUN chmod +x payload.sh

ENTRYPOINT ["nginx", "-g", "daemon off;"]
