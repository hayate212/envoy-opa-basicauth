FROM envoyproxy/envoy:v1.22-latest
COPY envoy.yaml /etc/envoy/envoy.yaml
RUN chmod go+r /etc/envoy/envoy.yaml
EXPOSE 9901 10000