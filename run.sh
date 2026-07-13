#/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <build> or <exec>"
    exit 1
fi

if [ "$1" = "exec" ]; then
    docker run -it --rm -v "$(pwd):/src" alpine /bin/zsh
elif [ "$1" = "build" ]; then
    docker build -t alpine .
elif [ "$1" = "hbasheer" ]; then
    git add .; git commit -m "hamdhan pushed"; git push
fi