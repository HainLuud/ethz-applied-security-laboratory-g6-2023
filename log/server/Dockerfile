# syntax=docker/dockerfile:1

FROM rsyslog/syslog_appliance_alpine:latest

RUN apk add --no-cache \
    rsyslog-tls

RUN chown rsyslog:rsyslog /config /work /logs

USER rsyslog
