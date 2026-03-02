FROM node:20-alpine

# Outils de monitoring
RUN apk add --no-cache strace curl tcpdump coreutils findutils jq iptables

# Non-root user for npm install (privilege drop via su in sandbox-runner.sh)
RUN adduser -D sandboxuser

# Dossier de travail avec bonnes permissions
WORKDIR /sandbox
RUN chown sandboxuser:sandboxuser /sandbox

# Script d'analyse (sed strips Windows CRLF line endings)
COPY sandbox-runner.sh /sandbox/
RUN sed -i 's/\r$//' /sandbox/sandbox-runner.sh && chmod +x /sandbox/sandbox-runner.sh

# Preload script for runtime monkey-patching (time acceleration, API logging)
COPY preload.js /opt/preload.js

# Entrypoint runs as root for iptables/tcpdump/dmesg access.
# npm install is dropped to sandboxuser via su in sandbox-runner.sh.
# --security-opt no-new-privileges is set by the Docker run args in sandbox.js.
ENTRYPOINT ["/sandbox/sandbox-runner.sh"]