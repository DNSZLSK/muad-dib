FROM node:20-alpine

# Outils de monitoring
RUN apk add --no-cache strace curl tcpdump

# User non-root
RUN adduser -D sandboxuser

# Dossier de travail avec bonnes permissions
WORKDIR /sandbox
RUN chown sandboxuser:sandboxuser /sandbox

# Script d'analyse
COPY sandbox-runner.sh /sandbox/
RUN chmod +x /sandbox/sandbox-runner.sh

USER sandboxuser

ENTRYPOINT ["/sandbox/sandbox-runner.sh"]