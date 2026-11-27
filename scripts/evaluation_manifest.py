import importlib.metadata as metadata
import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import httpx

from lab.policy import require

ROOT = Path(__file__).resolve().parents[1]


def verify_manifest():
    manifest = json.loads((ROOT / "results/manifest.json").read_text(encoding="utf-8"))
    require(f"Python {sys.version.split()[0]}" == manifest["python"], "Python differs from evaluation manifest")
    for name, expected in manifest["files"].items():
        require(sha256((ROOT / name).read_bytes()).hexdigest() == expected, f"Configuration hash differs: {name}")
    for line in (ROOT / "requirements-evaluation.txt").read_text(encoding="utf-8").splitlines():
        name, version = line.split("==", 1)
        require(metadata.version(name) == version, f"Dependency differs: {name}=={version}")
    images = manifest["images"]
    result = subprocess.run(("docker", "inspect", "--type", "image", *images), capture_output=True,
                            check=True, text=True, timeout=15)
    for name, actual in zip(images, json.loads(result.stdout), strict=True):
        require({"id": actual["Id"], "repo_digests": sorted(actual["RepoDigests"])} == images[name],
                f"Cached image differs: {name}")
    model = manifest["model"]
    response = httpx.get("http://127.0.0.1:11434/api/tags", trust_env=False, timeout=5)
    response.raise_for_status()
    require(any(row["name"] == model["name"] and row["digest"] == model["digest"]
                for row in response.json()["models"]), f"Cached model differs: {model['name']}")
    return manifest


if __name__ == "__main__":
    verified = verify_manifest()
    print(f"Verified {len(verified['files'])} files, {len(verified['images'])} image digests and {verified['model']['name']}")
