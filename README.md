# p4-nat
sudo ./bmv2/run_bm.sh
sudo ./bmv2/run_drivers.sh
sudo bash /home/p4/Desktop/repos/switch/tools/veth_setup.sh
sudo bash /home/p4/Desktop/repos/switch/tools/veth_teardown.sh



Simple Router: from https://github.com/p4lang/behavioral-model

To compile the p4 code:
p4c-bm --json <path to JSON file> <path to P4 file>
p4c-bmv2 simple_router.p4 --json simple_router.json

First Terminal
#cd mininet
sudo python ~/Desktop/repos/p4-nat/p4-nat/mininet/1sw_demo.py --behavioral-exe /home/p4/Desktop/repos/p4-nat/p4-nat/simple_router --json /home/p4/Desktop/repos/p4-nat/p4-nat/simple_router.json 

Second Terminal
cd targets/simple_router
./runtime_CLI < commands.txt_drop



## Testing: 

sudo ./send.py 10.0.1.10 "HIIIII" veth2
sudo ./receive.py veth4
