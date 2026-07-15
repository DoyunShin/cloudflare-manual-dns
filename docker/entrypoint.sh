#!/bin/sh
if [ "$#" -gt 0 ]; then exec "$@" || exit $?; fi
exec gunicorn -k uvicorn.workers.UvicornWorker -w ${WEB_CONCURRENCY:-4} -b 0.0.0.0:8080 cfproxy.main:app
