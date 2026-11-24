#!/usr/bin/env python3
"""Write a CycloneDX 1.5 SBOM for BaoBuddy's SwiftPM dependencies.

Usage: swift package show-dependencies --format json > deps.json
       python3 scripts/sbom.py deps.json baobuddy-sbom.cdx.json
"""
import datetime
import json
import sys
import uuid


def main(deps_path: str, out_path: str) -> None:
    with open(deps_path) as fh:
        root = json.load(fh)
    seen = {}

    def walk(node):
        for dep in node.get("dependencies", []):
            name = dep.get("identity") or dep.get("name")
            if name and name not in seen:
                version = dep.get("version", "unspecified")
                seen[name] = {
                    "type": "library",
                    "name": dep.get("name", name),
                    "version": version,
                    "purl": f"pkg:swift/{dep.get('name', name)}@{version}",
                    "externalReferences": [{"type": "vcs", "url": dep["url"]}] if dep.get("url") else [],
                }
            walk(dep)

    walk(root)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "component": {"type": "application", "name": "BaoBuddy"},
        },
        "components": sorted(seen.values(), key=lambda c: c["name"]),
    }
    with open(out_path, "w") as fh:
        json.dump(sbom, fh, indent=2)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
