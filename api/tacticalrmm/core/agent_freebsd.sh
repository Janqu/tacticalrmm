#!/bin/sh
#
# FreeBSD / OPNsense installer.
#
# The agent binary installs and manages its own rc.d service
# (see install.go / agent_unix.go in rmmagent), so this script only
# needs to fetch the binary and run "-m install" once.

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must be run as root"
    exit 1
fi

agentDL='agentDLChange'
apiURL='apiURLChange'
token='tokenChange'
clientID='clientIDChange'
siteID='siteIDChange'
agentType='agentTypeChange'

agentBinPath='/usr/local/bin'
binName='tacticalagent'
agentBin="${agentBinPath}/${binName}"
rcScript='/usr/local/etc/rc.d/tacticalagent'

RemoveOldAgent() {
    if [ -f "${rcScript}" ]; then
        service tacticalagent stop >/dev/null 2>&1
        sysrc -x tacticalagent_enable >/dev/null 2>&1
        rm -f "${rcScript}"
    fi
    rm -f /etc/tacticalagent
    rm -rf /opt/tacticalagent
}

if [ "$1" = "uninstall" ] || [ "$1" = "-uninstall" ] || [ "$1" = "--uninstall" ]; then
    RemoveOldAgent
    rm -f "$0"
    exit 0
fi

RemoveOldAgent

echo "Downloading tactical agent..."
fetch -q -o "${agentBin}" "${agentDL}"
if [ $? -ne 0 ]; then
    echo "ERROR: Unable to download tactical agent"
    exit 1
fi
chmod +x "${agentBin}"

"${agentBin}" -m install -api "${apiURL}" -client-id "${clientID}" -site-id "${siteID}" -agent-type "${agentType}" -auth "${token}" -nomesh
