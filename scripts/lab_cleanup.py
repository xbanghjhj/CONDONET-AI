import argparse
import json
import re
import subprocess
from pathlib import Path

from lab.policy import CheckFailed, require
from lab.topology import HOST_BY_NAME, container_name


NODES = {*HOST_BY_NAME, "sw", "gw", "wan"}


def docker(*args):
    return subprocess.run(("docker", *args), capture_output=True, text=True, check=True, timeout=30).stdout


def inventory(lab):
    ids = docker("ps", "-aq", "--no-trunc", "--filter", f"label=containerlab={lab}").splitlines()
    return json.loads(docker("container", "inspect", *ids)) if ids else []


def cleanup_targets(lab, topology, deployment, live):
    require(re.fullmatch(r"condonet-day(?:02|09|10)-[a-z0-9-]+", lab) and len(lab) <= 63,
            "A dedicated recovery or evaluation lab name is required")
    require(set(deployment) == {lab}, "Deployment receipt does not identify only the requested lab")
    rows = deployment[lab]
    names = {container_name(lab, node): node for node in NODES}
    recorded = {row["name"]: row for row in rows}
    current = {row["Name"].removeprefix("/"): row for row in live}
    require(len(rows) == len(live) == len(names) and recorded.keys() == current.keys() == names.keys(),
            "Deployment receipt and runtime must identify the same eight nodes")
    targets = []
    for name, node in sorted(names.items()):
        original, runtime = recorded[name], current[name]
        labels = runtime["Config"]["Labels"]
        identifier = original["container_id"]
        require(original["lab_name"] == lab and Path(original["absLabPath"]).resolve() == topology
                and labels["containerlab"] == lab and labels["clab-node-name"] == node
                and Path(labels["clab-topo-file"]).resolve() == topology
                and runtime["HostConfig"]["NetworkMode"] == "none"
                and re.fullmatch(r"[0-9a-f]{12,64}", identifier)
                and re.fullmatch(r"[0-9a-f]{64}", runtime["Id"]) and runtime["Id"].startswith(identifier),
                f"Runtime identity differs from deployment receipt for {name}")
        targets.append((name, runtime["Id"]))
    return targets


def main():
    parser = argparse.ArgumentParser(description="Preview or remove only the node IDs in a dedicated lab deployment receipt.")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--topology", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        deployment = json.loads(args.receipt.read_text(encoding="utf-8"))
        topology = args.topology.resolve(strict=True)
        targets = cleanup_targets(args.lab, topology, deployment, inventory(args.lab))
        for name, identifier in targets:
            print(f"{name} {identifier}", flush=True)
        if args.apply:
            require(cleanup_targets(args.lab, topology, deployment, inventory(args.lab)) == targets,
                    "Inventory changed after preview")
            docker("container", "rm", "--force", *(identifier for _, identifier in targets))
            require(not inventory(args.lab), "Unexpected nodes remain under the requested label")
    except (CheckFailed, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
