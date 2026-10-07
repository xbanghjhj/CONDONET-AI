# Nghiem thu ngay 1

## Moi truong
- Tai khoan Ubuntu: xbang@xbang
- Model: qwen3.5:2b
- ID da quan sat: 0689d44085e0
- Dung luong model tren dia: 2.7 GB
- Thiet bi suy luan: CPU, ollama ps hien thi 100% CPU
- Digest day du: 0689d44085e06d165161a8a9a1731344278cfb5aade63a3c3dbdb48ab54b130a
- Context da chon: 4096
- RAM Windows: Tong 31.79 GiB; con 19.19 GiB tai thoi diem do
- RAM VM: Ubuntu nhin thay 7.2 GiB
- So vCPU: 4 CPU kha dung theo nproc

## Lab
- Docker hello-world: DAT - hien thi Hello from Docker!
- Bridge va VLAN test: DAT - bridge co vlan_filtering 1; interface VLAN co protocol 802.1Q id 20
- Ping pc1 -> pc2: DAT - 5 goi gui, 5 goi nhan, 0% packet loss; RTT min/avg/max/mdev = 0.026/0.053/0.137/0.042 ms
- Ping pc2 -> pc1: CHUA XAC NHAN - chua co log phep ping khoi tao tu pc2
- PCAP co ARP va ICMP: DAT - log co 2 ARP request, 2 ARP reply, 5 ICMP echo request va 5 ICMP echo reply

## AI
- Thu muc benchmark duoc chon: /home/xbang/condonet-ai/evidence/day01/model-20261007T164345978799Z
- So luot da chay: 4
- So luot dat: 4/4; all_four_ok = True
- Cold latency: 9.732 giay; status = ok
- Warm median: 3.263 giay
- Warm max: 3.285 giay
- RAM available khi suy luan: Chua xac nhan truc tiep; snapshot khi model duoc nap cho thay available = 3.0 GiB
- Hoat dong swap: Hai snapshot hien thi used = 648 KiB va 14 MiB; chua co log si/so de ket luan swap in/out trong benchmark
- Tinh trang Windows: Snapshot RAM con 19.19 GiB; chua co so lieu CPU va quan sat do muot trong benchmark
