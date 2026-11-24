"""Select PR checks from the merge diff and validate the required CI Gate."""
import json
import os
import subprocess
import sys

IOS = {"ios-ci", "ios-app-tests"}
MAC = {"core-and-mac"}
RECEIVER = {"receiver-and-e2e", "vault-e2e"}
ALL = IOS | MAC | RECEIVER


def checks_for(path):
    if path.startswith(b"receiver/"):
        internal_only = path.startswith((
            b"receiver/internal/config/", b"receiver/internal/otel/", b"receiver/internal/openbao/",
        )) or path in {
            b"receiver/internal/receiver/install_transaction.go",
            b"receiver/internal/receiver/grant_files.go",
        }
        # Changes to command handlers, wire types or unfamiliar Go packages can affect both clients.
        if path.endswith(b".go") and not path.endswith(b"_test.go") and not internal_only:
            return ALL
        return RECEIVER | MAC
    if path.startswith((b"MacHelper/", b"Sources/BaoBuddyHelper/", b"Tests/BaoBuddyHelperTests/")):
        return MAC
    if path == b"BaoBuddy/AppIcon.icon" or path.startswith(b"BaoBuddy/AppIcon.icon/"):
        return ALL
    if path.startswith((b"BaoBuddy/", b"BaoBuddyTests/", b"BaoBuddyUITests/", b"BaoBuddyLiveActivity/", b"BaoBuddy.xcodeproj/")):
        return IOS
    # Shared Swift, CI, and unfamiliar paths get the full suite.
    return ALL


def plan():
    required = ALL
    if os.environ["GITHUB_EVENT_NAME"] == "pull_request" and os.environ["SCOPED_PR_CI"] == "true":
        # Compare the tested merge tree with its base parent. Include both sides of renames.
        paths = subprocess.check_output(["git", "diff", "--no-renames", "--name-only", "-z", "HEAD^1", "HEAD"]).split(b"\0")
        required = set().union(*(checks_for(path) for path in paths if path)) or ALL
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        print("required=" + json.dumps(sorted(required)), file=output)


def gate(needs):
    planner = needs["plan"]
    if set(needs) != ALL | {"plan"} or planner["result"] != "success":
        raise SystemExit("CI plan failed or job list does not match the gate")
    selected = json.loads(planner["outputs"]["required"])
    if not isinstance(selected, list) or not selected or not set(selected) <= ALL:
        raise SystemExit("Invalid CI plan")
    for name in sorted(ALL):
        expected = "success" if name in selected else "skipped"
        actual = needs[name]["result"]
        print(f"{name}: {actual} (expected {expected})")
        if actual != expected:
            raise SystemExit(f"Unexpected result for {name}")


if __name__ == "__main__":
    if sys.argv[1:] == ["plan"]:
        plan()
    elif sys.argv[1:] == ["gate"]:
        gate(json.loads(os.environ["RESULTS"]))
    else:
        raise SystemExit("Expected plan or gate")
