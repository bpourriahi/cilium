#!/bin/bash

set -e

export K8S_VERSION=${K8S_VERSION:-1.19}
export LOCAL_BOX=k8s-box

echo "starting runtime vm"
export SERVER_BOX=$LOCAL_BOX
export SERVER_VERSION=0
unset PRELOAD_VM
VM_CPUS=4 vagrant up runtime --provision
