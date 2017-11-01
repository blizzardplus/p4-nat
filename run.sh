#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/env.sh

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

# Probably not very elegant but it works nice here: we enable interactive mode
# to be able to use fg. We start the switch in the background, sleep for 2
# minutes to give it time to start, then add the entries and put the switch
# process back in the foreground
set -m
$P4C_BM_SCRIPT simple_router.p4 --json simple_router.json
# This gets root permissions, and gives libtool the opportunity to "warm-up"
sudo $SWITCH_PATH >/dev/null 2>&1



if [ $1 = "router" ]; then
    sudo python ./mininet/1sw_demo.py --behavioral-exe \
        /home/p4/Desktop/repos/p4-nat/p4-nat/simple_router \
        --json /home/p4/Desktop/repos/p4-nat/p4-nat/simple_router.json
elif [ $1 = "switch" ]; then
    sudo $SWITCH_PATH simple_router.json \
        -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 \
        --nanolog ipc:///tmp/bm-0-log.ipc \
        --pcap &
else
    echo "Error!! Usage: ./run.sh [router|switch]"
    exit -1
fi
sleep 2
$CLI_PATH simple_router.json < commands.txt
echo "READY!!!"
fg



## OLD command
#sudo ./simple_router -i 0@veth1 -i 1@veth3 -i 2@veth5 -i 3@veth7 --pcap simple_router.json
