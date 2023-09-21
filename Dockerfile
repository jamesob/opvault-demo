FROM docker.io/library/python:3.11-bullseye

ENV UNAME=user
ARG UID=1000
ARG GID=1000
RUN groupadd -g $GID -o $UNAME && \
  useradd -m -u $UID -g $GID -o -d /home/$UNAME -s /bin/bash $UNAME && \
  echo $UNAME:password | chpasswd && \
  adduser $UNAME sudo

USER $UNAME
WORKDIR /home/$UNAME
COPY --chown=$UNAME:$GID ./requirements.txt .
RUN pip install -r requirements.txt
CMD ./main.py
