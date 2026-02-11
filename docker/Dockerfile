FROM node:20-alpine

# Outils de monitoring
RUN apk add --no-cache strace curl tcpdump coreutils findutils jq iptables

# User non-root
RUN adduser -D sandboxuser

# Dossier de travail avec bonnes permissions
WORKDIR /sandbox
RUN chown sandboxuser:sandboxuser /sandbox

# Script d'analyse (sed strips Windows CRLF line endings)
COPY sandbox-runner.sh /sandbox/
RUN sed -i 's/\r$//' /sandbox/sandbox-runner.sh && chmod +x /sandbox/sandbox-runner.sh

USER sandboxuser

ENTRYPOINT ["/sandbox/sandbox-runner.sh"]