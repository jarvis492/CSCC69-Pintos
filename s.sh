docker run --platform linux/amd64 --rm --name pintos -it -v "$(pwd):/pintos" \
    -w //pintos/src/threads thierrysans/pintos bash -c 'make'

