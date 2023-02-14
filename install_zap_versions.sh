#!/bin/bash
set -ex

# -n $line enables last line not being \n terminated
while read -r ZAP_VERSION || [ -n "$ZAP_VERSION" ]
do
    mkdir -p "/opt/zap-${ZAP_VERSION}"
    cd "/opt/zap-${ZAP_VERSION}" || exit 1
    curl --location "https://github.com/project-chip/zap/releases/download/${ZAP_VERSION}/zap-linux.zip" --output zap-linux.zip
    unzip zap-linux.zip
    rm zap-linux.zip
    # Only keep the cli version, since `zap` is 143MB and not usable (UI)
    rm zap
    ln -s "/opt/zap-${ZAP_VERSION}/zap-cli" "/usr/bin/zap-cli-${ZAP_VERSION}"
    mv "/usr/bin/zap-cli-${ZAP_VERSION}" "/usr/bin/zap-cli"
done < zap-versions.txt
