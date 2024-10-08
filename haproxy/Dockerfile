
#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "apply-templates.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#

FROM debian:buster-slim

# roughly, https://salsa.debian.org/haproxy-team/haproxy/-/blob/732b97ae286906dea19ab5744cf9cf97c364ac1d/debian/haproxy.postinst#L5-6
RUN set -eux; \
	groupadd --gid 99 --system haproxy; \
	useradd \
		--gid haproxy \
		--home-dir /var/lib/haproxy \
		--no-create-home \
		--system \
		--uid 99 \
		haproxy

ENV HAPROXY_URL http://www.haproxy.org/download/3.0/src/snapshot/haproxy-ss-LATEST.tar.gz
ENV DATAPLANEAPI_URL https://github.com/haproxytech/dataplaneapi/releases/download/v2.7.5/dataplaneapi_2.7.5_Linux_x86_64.tar.gz

# see https://sources.debian.net/src/haproxy/jessie/debian/rules/ for some helpful navigation of the possible "make" arguments
RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		gcc \
		libc6-dev \
		liblua5.3-dev \
		libpcre2-dev \
		libssl-dev \
		make \
		wget \
		zlib1g-dev \
		luarocks \
	; \
	rm -rf /var/lib/apt/lists/*; \
#	\
#	wget -O dataplaneapi_Linux_x86_64.tar.gz "$DATAPLANEAPI_URL"; \
#	tar -zxvf dataplaneapi_Linux_x86_64.tar.gz; \
#	chmod +x build/dataplaneapi; \
#	cp build/dataplaneapi /usr/local/bin/; \
	\
	wget -O haproxy.tar.gz "$HAPROXY_URL"; \
#	echo "$HAPROXY_SHA256 *haproxy.tar.gz" | sha256sum -c; \
	mkdir -p /usr/src/haproxy; \
	tar -xzf haproxy.tar.gz -C /usr/src/haproxy --strip-components=1; \
	rm haproxy.tar.gz; \
	\
	makeOpts=' \
		TARGET=linux-glibc \
		USE_GETADDRINFO=1 \
		USE_LUA=1 LUA_INC=/usr/include/lua5.3 \
		USE_OPENSSL=1 \
		USE_PCRE2=1 USE_PCRE2_JIT=1 \
		USE_ZLIB=1 \
	'; \
# https://salsa.debian.org/haproxy-team/haproxy/-/commit/53988af3d006ebcbf2c941e34121859fd6379c70
	dpkgArch="$(dpkg --print-architecture)"; \
	case "$dpkgArch" in \
		armel) makeOpts="$makeOpts ADDLIB=-latomic" ;; \
	esac; \
	\
	nproc="$(nproc)"; \
	eval "make -C /usr/src/haproxy -j '$nproc' all $makeOpts"; \
	eval "make -C /usr/src/haproxy install-bin $makeOpts"; \
	\
	mkdir -p /etc/haproxy; \
	cp -R /usr/src/haproxy/examples/errorfiles /etc/haproxy/errors; \
	rm -rf /usr/src/haproxy; \
	\
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; \
	find /usr/local -type f -executable -exec ldd '{}' ';' \
		| awk '/=>/ { print $(NF-1) }' \
		| sort -u \
		| xargs -r dpkg-query --search \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	\
# smoke test
	haproxy -v

# https://www.haproxy.org/download/1.8/doc/management.txt
# "4. Stopping and restarting HAProxy"
# "when the SIGTERM signal is sent to the haproxy process, it immediately quits and all established connections are closed"
# "graceful stop is triggered when the SIGUSR1 signal is sent to the haproxy process"
STOPSIGNAL SIGUSR1

ADD haproxy/dataplaneapi.yml /etc/haproxy/dataplaneapi.yml
ADD haproxy/docker-entrypoint.sh /usr/local/bin/
RUN ln -s usr/local/bin/docker-entrypoint.sh / # backwards compat
RUN apt update && apt install -y git lua5.3 liblua5.3-dev argon2 libargon2-dev luarocks
RUN git config --global url."https://".insteadOf git://
RUN luarocks install argon2
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# no USER for backwards compatibility (to try to avoid breaking existing users)
CMD ["haproxy", "-f", "/etc/haproxy/haproxy.cfg"]
