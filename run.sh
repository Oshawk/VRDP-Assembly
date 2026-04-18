#!/bin/sh

cd "$(dirname "$0")"
WD="$(pwd)"

mkdir -p .runtime
mkdir -p .runtime/jobs

cd grader
sudo docker build -t assembly-grader . || exit 1
cd ..

docker build -t prairielearn-password-authentication 'https://github.com/Oshawk/PrairieLearn.git#password_authentication' || exit 2

sudo docker run -it --rm -p 3000:3000 \
    -v "$WD/course:/course" \
    -v "$WD/.runtime/jobs:/jobs" \
    -e HOST_JOBS_DIR="$WD/.runtime/jobs" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --add-host=host.docker.internal:172.17.0.1 \
    -v "$WD/config.json:/PrairieLearn/config.json" \
    prairielearn-password-authentication \
    bash -c 'rm -r /PrairieLearn/*Course && /PrairieLearn/scripts/init.sh'
