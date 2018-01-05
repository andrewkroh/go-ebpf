FROM centos:7

RUN curl -L -O https://github.com/tidwall/jj/releases/download/v1.0.1/jj-1.0.1-linux-amd64.tar.gz && \
    tar xf jj-1.0.1-linux-amd64.tar.gz && \
    mv jj-1.0.1-linux-amd64/jj /usr/bin && \
    rm -rf jj-1.0.1-linux*

RUN curl -L -O $(curl https://api.github.com/repos/andrewkroh/go-ebpf/releases/latest | jj assets.0.browser_download_url) && \
    chmod a+x execsnoop && \
    mv execsnoop /usr/sbin

ADD docker-entrypoint.sh /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["execsnoop"]
