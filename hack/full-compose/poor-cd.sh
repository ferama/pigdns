#! /bin/bash
#
# This script periodically checks for up to date image in the remote container registry
# If it find any, pull it and recreates the local container using the new image
#

IMAGE=ghcr.io/ferama/pigdns
TAG=main
ARCHITECTURE=arm

TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:${IMAGE}:pull" | jq -r ".token")

req() { 
    curl -s \
        -H "Authorization: Bearer ${TOKEN}" \
        -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
        -H 'Accept: application/vnd.oci.image.index.v1+json' \
        "$1" 
}

log() {
    local color="\033[0;34m"
    local reset="\033[m"
    echo -e "${color}[$(date +%T)]${reset} $@"
}

while true
do
    remote_id=$(req "https://ghcr.io/v2/${IMAGE}/manifests/${TAG}" | 
        jq -r ".manifests[] | select(.platform.architecture==\"${ARCHITECTURE}\") | .digest")

    local_id=$(cat local_id)

    if [ "$remote_id" != "$local_id" ]
    then
        log "remoteId: $remote_id"
        log "localId: $local_id"
        log "==> needs update"
        docker compose pull pigdns
        docker compose down pigdns
        docker compose up -d pigdns
        echo $remote_id > local_id
    else
        log "no new image available"
    fi

    sleep 60
done

