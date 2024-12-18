
FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    apache2 \
    openssh-server

RUN mkdir /var/run/sshd

RUN echo 'root:root' | chpasswd

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

RUN ln -sf /dev/stdout /var/log/apache2/access.log \
    && ln -sf /dev/stderr /var/log/apache2/error.log

EXPOSE 80 22

CMD service ssh start && apache2ctl -D FOREGROUND

