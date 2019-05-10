FROM ubuntu:18.04

WORKDIR /gitkanban

ADD . /gitkanban

RUN apt-get -y update && apt-get install -y python3-dev python3-pip build-essential

RUN pip3 install .

ENTRYPOINT ["gitkanban"]
