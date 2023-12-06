#!/bin/bash
# This is a wrapper script allowing to use GCP's IAP option to connect
# to our servers.

# Ansible passes a large number of SSH parameters along with the hostname as the
# second to last argument and the command as the last. We will pop the last two
# arguments off of the list and then pass all of the other SSH flags through
# without modification:
host="${@: -2: 1}"
cmd="${@: -1: 1}"

# Unfortunately ansible has hardcoded scp options, so we need to filter these out
# It's an ugly hack, but for now we'll only accept the options starting with '--'
declare -a opts
for scp_arg in "${@: 1: $# -3}" ; do
        if [[ "${scp_arg}" == --* ]] ; then
                opts+="${scp_arg} "
        fi
done

# Remove [] around our host, as gcloud scp doesn't understand this syntax
cmd=`echo "${cmd}" | tr -d []`

exec gcloud compute scp $opts "${host}" "${cmd}"
