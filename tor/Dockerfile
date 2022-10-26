FROM alpine:latest
RUN apk update && apk add tor
COPY ./tor/torrc.default /etc/tor/torrc
ADD ./tor/hidden_service/ /var/lib/tor/hidden_service
RUN chmod -R 700 /var/lib/tor/
RUN chmod -R 600 /var/lib/tor/hidden_service/hs_ed25519_secret_key
RUN chown -R tor /var/lib/tor/
RUN chown -R tor /etc/tor
USER tor
ENTRYPOINT [ "tor" ]
CMD [ "-f", "/etc/tor/torrc" ]
