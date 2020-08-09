# Image with tools
# - nslookup
# - curl
# - nc

FROM alpine:3.11.3

RUN apk --no-cache add curl &&\
    apk update && apk add ca-certificates && rm -rf /var/cache/apk/*


COPY ./ca.pem /usr/local/share/ca-certificates/ca.pem

# RUN update-ca-certificates