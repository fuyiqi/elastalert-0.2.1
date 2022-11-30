FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get -y install ruby build-essential libssl-dev git gcc+ gcc libffi-dev zlib1g-dev \
    wget make openssl libsqlite3-dev tk-dev libncursesw5-dev libgdbm-dev libc6-dev curl

RUN wget https://www.python.org/ftp/python/3.6.5/Python-3.6.5.tgz  &&  \
    tar -xzvf Python-3.6.5.tgz && \
    cd Python-3.6.5 && \
    ./configure && \
    make install

RUN rm -rf /usr/bin/python3 && rm -rf /usr/bin/pip3

RUN ln -s /usr/local//bin/python3.6 /usr/bin/python3 && ln -s /usr/local/bin/pip3.6 /usr/bin/pip3

WORKDIR /home/elastalert

ADD requirements*.txt ./
RUN pip3 install -r requirements.txt



