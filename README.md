# Docker container starting multiple vrouter-nodemgr instances

## Preparation

Allow insecure docker registires (make sure that it contains the following string):

``` bash
cat /etc/docker/daemon.json
{
    "insecure-registries": ["tf-nexus.progmaticlab.com:5002"]
}
```

## Build image

``` bash
docker build -t nodemgr-throng  --build-arg CONTAINER_NAME="nodemgr-throng" --build-arg CONTRAIL_REGISTRY=tf-nexus.progmaticlab.com:5002 --build-arg CONTRAIL_CONTAINER_TAG=nightly --network host -f Dockerfile .
```

## Start the container
docker run -d -v /etc/contrail/ssl:/etc/contrail/ssl:ro -v /etc/hosts:/etc/hosts:ro -v /etc/localtime:/etc/localtime:ro -v /var/run:/var/run -v /var/lib/containers:/var/lib/containers -v /var/run/docker.sock:/mnt/docker.sock -v /var/lib/contrail/loadbalancer:/var/lib/contrail/loadbalancer --env INTROSPECT_SSL_ENABLE=<True|False> --env 'CONTROLLER_NODES=<comma separated list of controller host IP addresses>' --name <name of the container> --privileged --net host nodemgr-throng:latest <number of nodemgr instances to spawn>
