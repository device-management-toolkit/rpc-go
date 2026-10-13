#!/bin/bash

# Push the release images built in the prepare step.
# Prereleases push only their version tag to Docker Hub: the workflow logs into
# ACR only on the release branch, and :latest belongs to the stable release.

set -euo pipefail

version=$1

images=(docker.io/intel/oact-rpc-go docker.io/intel/device-mgmt-toolkit-rpc-go)

if [[ "$version" == *-* ]]; then
    for image in "${images[@]}"; do
        docker push "$image:v$version"
    done

    exit 0
fi

for image in vprodemo.azurecr.io/rpc-go "${images[@]}"; do
    docker push "$image:v$version"
    docker push "$image:latest"
done
