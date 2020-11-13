ARG CONTRAIL_REGISTRY
ARG CONTRAIL_CONTAINER_TAG
FROM ${CONTRAIL_REGISTRY}/contrail-nodemgr:${CONTRAIL_CONTAINER_TAG}

COPY src/entrypoint.sh /
COPY src/main.py /usr/lib/python2.7/site-packages/nodemgr/
COPY src/event_manager.py /usr/lib/python2.7/site-packages/nodemgr/common/
ENTRYPOINT ["/entrypoint.sh"]

ARG CONTAINER_NAME
LABEL name=$CONTAINER_NAME

