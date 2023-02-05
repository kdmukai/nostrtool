# Dockerfile

# Pull base image
FROM python:3.9-bullseye

# Set environment variables
# Don't write *.pyc files or create __pycache__ dirs
ENV PYTHONDONTWRITEBYTECODE 1

##### Set environment variables #####
# Stream python stdout back to calling shell
ENV PYTHONUNBUFFERED 1

RUN apt update -y
RUN apt upgrade -y
RUN apt dist-upgrade -y
RUN apt autoremove -y

# Prevent tzdata install from requiring user input
ENV DEBIAN_FRONTEND=noninteractive

# Install additional required tools
#                        wget git: basic utilities 
#                            nano: sane text editor
RUN apt install -y \
    wget curl git nano

# Set work directory
WORKDIR /code

# Set up the interactive bash shell to our liking
COPY docker/bashrc /root/.bashrc

# Create virtualenv
RUN apt install -y python3-virtualenv
RUN virtualenv -p /usr/bin/python3.9 /srv/.env

#********************** Set up LOCAL server env **********************
WORKDIR /srv
RUN git clone https://github.com/kdmukai/nostrtool.git

WORKDIR /srv/nostrtool
RUN git clone https://github.com/kdmukai/python-nostr.git

WORKDIR /srv/nostrtool/python-nostr
RUN git checkout dev

WORKDIR /srv/nostrtool
RUN /srv/.env/bin/pip install -r requirements.txt --no-cache-dir

WORKDIR /srv/nostrtool/src
RUN ln -s ../python-nostr/nostr/ nostr

# Zappa
RUN mkdir /root/.aws
RUN /srv/.env/bin/pip install zappa --no-cache-dir
