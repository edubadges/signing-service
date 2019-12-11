FROM centos:7
LABEL image="badges-base-server"
LABEL versie="0.1"
LABEL datum="2019 12 10"

#1. Install Python 3.7.0 on CentOS/RHEL 7
#2. Set up requirements
#3. Download Python 3.7.0:
#4. Install Python 3.7.0:
#5. Remove downloaded source archive file from your system:

# Install system dependencies and install Python 3.7
RUN yum -y install gcc libffi libffi-devel openssl-devel bzip2-devel wget make && \
    cd /usr/src && \
    wget https://www.python.org/ftp/python/3.7.0/Python-3.7.0.tgz && \
    tar xzf Python-3.7.0.tgz && \
    cd Python-3.7.0 && \
    ./configure --enable-optimizations && \
    make altinstall && \
    rm /usr/src/Python-3.7.0.tgz && \
    echo 'alias python3.7="python3"' >> ~/.bashrc

ENV SECRET_KEY 'verysecretanddifficultkey'

# prep signing-server for building
RUN yum -y install epel-release  && \
    yum -y makecache fast && \
    yum -y install python-pip kernel-devel kernel-headers python37-setuptools && \
    easy_install-3.7 pip

# setup webserver
RUN pip3 install gunicorn && \
    mkdir /var/log/gunicorn && \
    touch /var/log/gunicorn/error.log && \
    touch /var/log/gunicorn/access.log && \
    ln -sf /usr/share/zoneinfo/Europe/Amsterdam /etc/localtime
    
# setup signing-server
COPY ./signing-service /var/signing-service
RUN cd /var/signing-service && \
    pip3 install -r requirements.txt

COPY docker-entrypoint.sh /docker-entrypoint.sh
WORKDIR /var/signing-service

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD bash -c "gunicorn tsob.wsgi:application --bind 0.0.0.0:8000 --access-logfile /var/log/gunicorn/access.log --error-logfile /var/log/gunicorn/error.log --timeout 120"
