from dataclasses import dataclass


@dataclass(frozen=True)
class Host:
    name: str
    vlan: int
    port: str
    dhcp: bool = False

    @property
    def address(self):
        return f"10.60.{self.vlan}.10"

    @property
    def gateway(self):
        return f"10.60.{self.vlan}.1"


HOSTS = (
    Host("admin", 10, "eth2"),
    Host("resident", 20, "eth3", dhcp=True),
    Host("guest", 30, "eth4", dhcp=True),
    Host("camera", 40, "eth5"),
    Host("svc", 50, "eth6"),
)
HOST_BY_NAME = {host.name: host for host in HOSTS}
GATEWAYS = {f"gw-{host.name}": host.gateway for host in HOSTS}
WAN_ADDRESS = "10.60.254.2"
WAN_GATEWAY = "10.60.254.1"
DNS_ADDRESS = HOST_BY_NAME["svc"].address
DNS_RECORDS = {"portal.condo.test": DNS_ADDRESS, "internet.test": WAN_ADDRESS}
HTTP_BODY_MARKERS = {"portal": "CondoNet Portal", "camera": "CondoNet Camera"}


def container_name(lab, node):
    return f"clab-{lab}-{node}"
