FROM openpolicyagent/opa:0.43.0-envoy
COPY ["./config.yaml", "./"]
COPY ["./policy.rego", "./"]
EXPOSE 9191
CMD ["run", "--server", "--log-level", "debug", "-c", "config.yaml", "policy.rego"]