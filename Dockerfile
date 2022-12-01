FROM ubuntu:16.04

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get -y install ruby build-essential libssl-dev git gcc+ gcc libffi-dev zlib1g-dev \
    wget make openssl libsqlite3-dev tk-dev libncursesw5-dev libgdbm-dev libc6-dev curl libmagic1
#编译并安装python3.6
RUN wget https://www.python.org/ftp/python/3.6.5/Python-3.6.5.tgz  &&  \
    tar -xzvf Python-3.6.5.tgz && \
    cd Python-3.6.5 && \
    ./configure && \
    make install
#清理python安装包
RUN rm -rf /usr/bin/python* && rm -rf /usr/bin/pip* && rm -rf ../Python-3.6.5*
#创建python和pip软连接
RUN ln -s /usr/local//bin/python3.6 /usr/bin/python && curl https://bootstrap.pypa.io/pip/3.6/get-pip.py -o get-pip.py  \
    && python get-pip.py && rm -rf get-pip.py
#设置工作目录
WORKDIR /home/elastalert
#安装elastalert的依赖
ADD requirements.txt ./
RUN pip install -r requirements.txt && pip install elastalert
#替换二次开发工程
ADD elastalert .
RUN rm -rf /usr/local/lib/python3.6/site-packages/elastalert/* &&  \
    cp -r ../elastalert /usr/local/lib/python3.6/site-packages/ && \
    rm -rf *

ADD long.py ./
ENTRYPOINT ["python", "long.py"]


