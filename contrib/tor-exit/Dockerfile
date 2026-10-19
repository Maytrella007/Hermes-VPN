# Tor and privoxy from Alpine's own repositories, so what runs here comes from
# a distribution that signs its packages rather than from someone's image.
# One image, two containers: tor runs the tunnel, privoxy puts an HTTP face on
# it. Two processes in one container would need an init to reap and restart
# them, and this way docker does that job.
FROM alpine:3.21

RUN apk add --no-cache tor privoxy curl

COPY torrc /etc/tor/torrc
COPY privoxy.conf /etc/privoxy/config

# Both packages create their own user; tor's data directory has to belong to
# it or tor refuses to start.
RUN chown -R tor:tor /var/lib/tor /etc/tor \
 && chmod 700 /var/lib/tor

USER tor
CMD ["tor", "-f", "/etc/tor/torrc"]
