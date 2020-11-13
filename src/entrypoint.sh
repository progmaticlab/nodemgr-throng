#!/bin/bash

set -o allexport
NODE_TYPE=vrouter
NODEMGR_TYPE=contrail-${NODE_TYPE}
set +o allexport

source /common.sh

pre_start_init

# Env variables:
# NODE_TYPE = name of the component [vrouter, config, control, analytics, database, config-database, toragent]

set_vnc_api_lib_ini

NODEMGR_NAME=${NODEMGR_TYPE}-nodemgr

ntype=`echo ${NODE_TYPE^^} | tr '-' '_'`

# Ensure vhost0 is up.
# Nodemgr in vrouter mode is run on the node with vhost0.
# During vhost0 initialization there is possible race between
# the host_ip deriving logic and vhost0 initialization
if ! wait_nic_up vhost0 ; then
  echo "ERROR: vhost0 is not up .. exit to allow docker policy to restart container if needed"
  exit 1
fi

hostip=$(get_ip_for_vrouter_from_control)
host_name=${VROUTER_HOSTNAME:-}

introspect_ip='0.0.0.0'
if ! is_enabled ${INTROSPECT_LISTEN_ALL} ; then
  introspect_ip=$hostip
fi

m=nodemgr-throng
e=/var/run/${m}/configs
l=/var/log/${m}
r=/var/run/${m}/ports
rm -rf ${e} ${r}
mkdir -p ${e} ${l} ${r}

function spawn() {
  local i=$1
  local c=${e}/instance${i}.conf
  shift

  local h=$(printf "${m}-%04d" $i).$(hostname -f)
  cat > ${c} << EOM
[DEFAULTS]
http_server_ip=$introspect_ip
log_file=$l/instance${i}.log
log_level=$LOG_LEVEL
log_local=$LOG_LOCAL
hostip=${hostip}
db_port=${CASSANDRA_CQL_PORT}
db_jmx_port=${CASSANDRA_JMX_LOCAL_PORT}
db_use_ssl=$(format_boolean $CASSANDRA_SSL_ENABLE)
hostname=${h}
port_stash=${r}

[COLLECTOR]
server_list=${COLLECTOR_SERVERS}

$collector_stats_config
EOM

  add_ini_params_from_env ${ntype}_NODEMGR ${c}

  exec /usr/bin/contrail-nodemgr --nodetype=${NODEMGR_TYPE} --config=${c}
}

n=0
if ((0 < $#))
then
  n=$((0 + $1))
fi
if ((0 >= $n))
then
  n=1
fi

p=()
for ((i=1; i <= ${n}; ++i))
do
  spawn $i $@ &
  p+=("$!")
done
wait ${p[*]}
