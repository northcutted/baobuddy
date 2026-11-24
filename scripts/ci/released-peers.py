"""Select the most recently published stable release in each product's tag namespace."""
import json
import os
import re
import sys

pages = json.load(sys.stdin)
if not isinstance(pages, list) or not pages or not all(isinstance(page, list) for page in pages):
    raise SystemExit("Expected paginated GitHub release lists")
releases = sorted((r for page in pages for r in page if not r["draft"] and not r["prerelease"]),
                  key=lambda r: (r["published_at"], r["id"]), reverse=True)
with open(os.environ["GITHUB_OUTPUT"], "a") as output:
    for product, prefix in (("ios", "v"), ("helper", "helper-v"), ("receiver", "receiver-v")):
        tag = next((r["tag_name"] for r in releases
                    if re.fullmatch(prefix + r"[0-9]+\.[0-9]+\.[0-9]+", r["tag_name"])), "")
        print(f"{product}={tag}", file=output)
        print(f"{product}: {tag or 'awaiting first stable release'}")
