from dataclasses import dataclass

import pytest

from lab.policy import CheckFailed
from lab.topology import container_name
from scripts import lab_cleanup


@dataclass
class Instance:
    report: dict
    containers: list


def instance(lab, topology, prefix):
    report = []
    containers = []
    for index, node in enumerate(sorted(lab_cleanup.NODES)):
        name = container_name(lab, node)
        identifier = f"{prefix}{index:011x}" + "0" * 52
        report.append({"name": name, "lab_name": lab, "absLabPath": str(topology),
                       "container_id": identifier[:12]})
        containers.append({"Name": f"/{name}", "Id": identifier, "HostConfig": {"NetworkMode": "none"},
                           "Config": {"Labels": {"containerlab": lab, "clab-node-name": node,
                                                 "clab-topo-file": str(topology)}}})
    return Instance({lab: report}, containers)


def test_cleanup_uses_only_receipted_ids_with_shared_yaml(tmp_path, monkeypatch, capsys):
    import json
    import sys

    topology = tmp_path / "condonet.clab.yml"
    topology.write_text("name: condonet\n")
    target = instance("condonet-day09-session", topology, "a")
    external = instance("condonet", topology, "b")
    active = {row["Id"]: row for row in target.containers + external.containers}
    receipt = tmp_path / "deploy.json"
    receipt.write_text(json.dumps(target.report))

    def docker(*args):
        if args[0] == "ps":
            lab = args[-1].removeprefix("label=containerlab=")
            return "\n".join(k for k, v in active.items() if v["Config"]["Labels"]["containerlab"] == lab)
        if args[1] == "inspect":
            return json.dumps([active[identifier] for identifier in args[2:]])
        assert args[:3] == ("container", "rm", "--force")
        preview = capsys.readouterr().out
        for identifier in args[3:]:
            assert identifier in preview
            del active[identifier]
        return ""

    monkeypatch.setattr(lab_cleanup, "docker", docker)
    args = ["lab_cleanup", "--lab", "condonet-day09-session", "--topology", str(topology),
            "--receipt", str(receipt)]
    monkeypatch.setattr(sys, "argv", args)
    lab_cleanup.main()
    assert len(active) == 16 and "clab-condonet-day09-session-sw" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", args + ["--apply"])
    lab_cleanup.main()
    assert set(active) == {row["Id"] for row in external.containers}


def test_cleanup_refuses_replacement_id(tmp_path):
    lab = "condonet-day09-session"
    topology = tmp_path / "condonet.clab.yml"
    target = instance(lab, topology, "a")
    current = instance(lab, topology, "b")
    with pytest.raises(CheckFailed, match="identity differs"):
        lab_cleanup.cleanup_targets(lab, topology, target.report, current.containers)
