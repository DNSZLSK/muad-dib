#!/bin/bash

# Normal curl usage (no pipe to shell)
curl -o output.json https://api.example.com/data

# Normal eval usage (no curl)
eval "echo hello world"

# Normal sh usage (no curl)
sh -c 'echo test'
