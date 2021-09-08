#!/bin/bash

# Colored text
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
OFF='\033[0m'

# Add sym link for python
PYTHON=/usr/bin/python

if test -f "$PYTHON"; then
    echo -e "${GREEN}Post processing checks complete." 
else 
    echo "training" | sudo -S ln -s /usr/bin/python3 /usr/bin/python > /dev/null
    echo -e "${GREEN}Python symbolic link added."
fi
