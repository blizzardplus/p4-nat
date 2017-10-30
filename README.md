# p4-nat
sudo ./bmv2/run_bm.sh
sudo ./bmv2/run_drivers.sh
sudo bash /home/p4/Desktop/repos/switch/tools/veth_setup.sh
sudo bash /home/p4/Desktop/repos/switch/tools/veth_teardown.sh



Simple Router: from https://github.com/p4lang/behavioral-model

To compile the p4 code:
p4c-bm --json <path to JSON file> <path to P4 file>

First Terminal
#cd mininet
sudo python /home/p4/Desktop/repos/behavioral-model/mininet/1sw_demo.py --behavioral-exe ./simple_router --json ./simple_router.json

Second Terminal
cd targets/simple_router
./runtime_CLI < commands.txt