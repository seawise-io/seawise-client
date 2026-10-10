#!/usr/bin/env python3
"""Run the agent image the way each packaging template does and check it.

  packaging/test-templates.py IMAGE

For every template: the settings are hardened (read-only root, ALL
capabilities dropped, at most CHOWN/SETUID/SETGID added, no-new-privileges,
no host network, no secrets, a v2 channel tag), the container becomes
healthy, the agent runs as the template's user and group with no
capabilities and no root group, the root filesystem cannot be written, and
root-owned files left by older images are handed over. The entrypoint must
refuse every way of running the agent as root.

Containers run with --network none and are named seawise-pkgtest-*; the template's
image is replaced by IMAGE and its host folder by a temporary one. Needs
docker with the compose plugin.
"""
import json
import os
import re
import shlex
import shutil
import tarfile
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "seawise-pkgtest-"
ALLOWED_CAPS = {"CHOWN", "SETUID", "SETGID"}
IMAGE_REPO = "ghcr.io/seawise-io/seawise-client"
CHANNEL = re.compile(r"^(beta|stable|2|2\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))\Z")
SECRET_NAME = re.compile(r"(PASSWORD|TOKEN|SECRET|KEY)", re.I)
HEALTH_TIMEOUT = 90

failures = []


def check(ok, what):
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failures.append(what)
    return ok


def docker(*args, check_rc=True, timeout=120):
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        p = subprocess.CompletedProcess(e.cmd, 124, e.stdout or "", "timed out")
        if isinstance(p.stdout, bytes):
            p.stdout = p.stdout.decode(errors="replace")
    if check_rc and p.returncode != 0:
        raise RuntimeError("docker %s: %s" % (" ".join(args), p.stderr.strip()))
    return p


class Template:
    """A template reduced to what matters for docker run."""

    def __init__(self, name):
        self.name = name
        self.image = ""
        self.user = ""
        self.read_only = False
        self.cap_drop = []
        self.cap_add = []
        self.security_opt = []
        self.env = {}
        self.volumes = []  # container targets
        self.privileged = False
        self.network = ""
        self.ports = []  # (host_ip, published)


def load_compose(name, path):
    out = docker("compose", "-f", path, "config", "--format", "json").stdout
    svc = json.loads(out)["services"]["seawise"]
    t = Template(name)
    t.image = svc.get("image", "")
    t.user = svc.get("user", "")
    t.read_only = bool(svc.get("read_only"))
    t.cap_drop = svc.get("cap_drop") or []
    t.cap_add = svc.get("cap_add") or []
    t.security_opt = svc.get("security_opt") or []
    t.env = svc.get("environment") or {}
    t.volumes = [v["target"] for v in svc.get("volumes") or []]
    t.privileged = bool(svc.get("privileged"))
    t.network = svc.get("network_mode", "")
    t.ports = [(p.get("host_ip", ""), p.get("published", "")) for p in svc.get("ports") or []]
    return t


def load_unraid(name, path):
    root = ET.parse(path).getroot()
    t = Template(name)
    t.image = root.findtext("Repository", "")
    t.privileged = root.findtext("Privileged", "") != "false"
    t.network = root.findtext("Network", "")
    args = shlex.split(root.findtext("ExtraParams", ""))
    i = 0
    while i < len(args):
        a, v = args[i], args[i + 1] if i + 1 < len(args) else ""
        if a == "--read-only":
            t.read_only = True
            i += 1
            continue
        if a == "--cap-drop":
            t.cap_drop.append(v)
        elif a == "--cap-add":
            t.cap_add.append(v)
        elif a == "--security-opt":
            t.security_opt.append(v)
        elif a == "--user":
            t.user = v
        elif a == "--restart":
            pass
        else:
            raise RuntimeError("%s: unexpected ExtraParams %r" % (name, a))
        i += 2
    for c in root.iter("Config"):
        if c.get("Type") == "Variable":
            t.env[c.get("Target")] = c.text or c.get("Default", "")
        elif c.get("Type") == "Path":
            t.volumes.append(c.get("Target"))
    return t


def load_homeassistant(name, path):
    """Home Assistant decides most container options itself; check what the
    stub declares and run it with Docker's defaults."""
    text = open(path, encoding="utf-8").read()
    t = Template(name)
    for key in ("privileged", "host_network", "full_access", "host_pid", "apparmor", "docker_api"):
        check(not re.search(r"^%s:" % key, text, re.M), "%s: does not set %s" % (name, key))
    image = re.search(r"^image: *(\S+)", text, re.M).group(1)
    version = re.search(r"^version: *(\S+)", text, re.M).group(1)
    check(":" not in image.split("/")[-1], "%s: image has no tag (the add-on version is the tag)" % name)
    t.image = "%s:%s" % (image, version)
    env = re.search(r"^environment:\n((?:  .*\n)+)", text, re.M).group(1)
    for line in env.splitlines():
        k, v = line.strip().split(":", 1)
        t.env[k.strip()] = v.strip().strip('"')
    t.volumes = [t.env.get("SEAWISE_DATA_DIR", "/config")]
    return t


def static_checks(t):
    n = t.name
    repo, _, tag = t.image.rpartition(":")
    check(repo == IMAGE_REPO and bool(CHANNEL.match(tag)), "%s: image %s is on a v2 channel" % (n, t.image))
    check(not t.privileged, "%s: not privileged" % n)
    check(t.network in ("", "bridge"), "%s: no host network" % n)
    for k, v in t.env.items():
        check(not SECRET_NAME.search(k) or k.endswith("_FILE"), "%s: no secret in environment %s" % (n, k))
    data = t.env.get("SEAWISE_DATA_DIR", "/config")
    check(data in t.volumes, "%s: data folder %s is a volume" % (n, data))
    if n == "compose":
        check(t.ports and all(ip == "127.0.0.1" for ip, _ in t.ports), "%s: admin UI published on 127.0.0.1 only %s" % (n, t.ports))
    if n == "homeassistant":
        return
    check(t.read_only, "%s: read-only root filesystem" % n)
    check(t.cap_drop == ["ALL"], "%s: drops ALL capabilities" % n)
    check(set(t.cap_add) <= ALLOWED_CAPS, "%s: adds only CHOWN, SETUID, SETGID" % n)
    if t.user:
        check(not t.cap_add, "%s: adds no capabilities when started as a user" % n)
    check(any(o.startswith("no-new-privileges") and not o.endswith(":false") for o in t.security_opt), "%s: no-new-privileges" % n)


def expected_ids(t):
    if t.user:
        u, _, g = t.user.partition(":")
        return u, g or u
    return t.env.get("PUID", "1000"), t.env.get("PGID", "1000")


def helper(image, folder, script):
    """Run a shell as root with Docker's default capabilities on folder."""
    return docker("run", "--rm", "--network", "none", "--entrypoint", "sh", "-v", folder + ":/d", image, "-c", script)


def cleanup(image, folder):
    helper(image, folder, "rm -rf /d/* /d/.[!.]*; chown %d:%d /d" % (os.getuid(), os.getgid()))
    shutil.rmtree(folder)


# Root-owned files and folders as an older image running as root leaves
# them, under a root-owned 0700 data folder. machine.json marks it as a
# SeaWise data folder.
SEED = """set -e
echo '{"machine_id":"pkgtest","machine_name":"pkgtest","services":[]}' > /d/machine.json
mkdir -p /d/legacy/nested
echo state > /d/notes.txt
echo nested > '/d/legacy/nested/a file'
ln -s /etc/passwd /d/link
chmod 600 /d/machine.json /d/notes.txt '/d/legacy/nested/a file'
chmod 700 /d /d/legacy /d/legacy/nested
chown -R 0:0 /d
chown -h 0:0 /d/link
"""


def status(name):
    out = docker("exec", name, "cat", "/proc/1/status").stdout
    return dict(line.split(":\t", 1) for line in out.splitlines() if ":\t" in line)


def wait_healthy(name):
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        st = json.loads(docker("inspect", name).stdout)[0]["State"]
        h = (st.get("Health") or {}).get("Status")
        if h == "healthy":
            return True
        if not st["Running"]:
            break
        time.sleep(1)
    print(docker("logs", name, check_rc=False).stderr[-2000:])
    return False


def run_template(t, image, seed=SEED):
    n = t.name
    name = PREFIX + n
    data = t.env.get("SEAWISE_DATA_DIR", "/config")
    uid, gid = expected_ids(t)
    folder = tempfile.mkdtemp(prefix=PREFIX)
    try:
        if t.user:
            helper(image, folder, "chown %s:%s /d && chmod 700 /d" % (uid, gid))
        else:
            helper(image, folder, seed)
        args = ["run", "-d", "--name", name, "--network", "none", "--health-interval", "2s", "-v", folder + ":" + data]
        if t.user:
            args += ["--user", t.user]
        if t.read_only:
            args.append("--read-only")
        for c in t.cap_drop:
            args += ["--cap-drop", c]
        for c in t.cap_add:
            args += ["--cap-add", c]
        for o in t.security_opt:
            args += ["--security-opt", o]
        for k, v in t.env.items():
            args += ["-e", "%s=%s" % (k, v)]
        docker(*args, image)
        for attempt in ("start", "restart"):
            if attempt == "restart":
                docker("restart", name)
            if not check(wait_healthy(name), "%s: healthy after %s" % (n, attempt)):
                return
            s = status(name)
            check(s["Uid"].split() == [uid] * 4, "%s: agent uid %s (%s)" % (n, uid, s["Uid"].strip()))
            check(s["Gid"].split() == [gid] * 4, "%s: agent gid %s (%s)" % (n, gid, s["Gid"].strip()))
            check(s["Groups"].split() in ([], [gid]), "%s: no extra groups (%s)" % (n, s["Groups"].strip()))
            for cap in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
                check(int(s[cap], 16) == 0, "%s: %s is empty" % (n, cap))
            check(s["NoNewPrivs"].strip() == "1", "%s: NoNewPrivs" % n)
        logs = docker("logs", name).stderr
        check("WARNING" not in logs, "%s: no handover warnings" % n)
        hc = json.loads(docker("inspect", name).stdout)[0]["HostConfig"]
        check(hc["ReadonlyRootfs"] == t.read_only, "%s: ReadonlyRootfs is %s" % (n, t.read_only))
        if t.read_only:
            for p in ("/", "/app", "/etc", "/tmp", "/usr"):
                w = docker("exec", "-u", "0", name, "touch", p.rstrip("/") + "/.w", check_rc=False)
                check(w.returncode != 0, "%s: %s is not writable" % (n, p))
        w = docker("exec", "-u", "%s:%s" % (uid, gid), name, "sh", "-c", "touch %s/.w && rm %s/.w" % (data, data), check_rc=False)
        check(w.returncode == 0, "%s: %s is writable by the agent" % (n, data))
        left = helper(image, folder, "find /d -user 0 ! -path /d; find /d ! -user %s; stat -c %%u:%%g /d" % uid).stdout.split()
        check(left == ["%s:%s" % (uid, gid)], "%s: everything in %s owned by %s:%s %s" % (n, data, uid, gid, left[:-1] or ""))
        if not t.user and seed == SEED:
            h = helper(image, folder, "cat /d/notes.txt '/d/legacy/nested/a file'; readlink /d/link").stdout.split()
            check(h == ["state", "nested", "/etc/passwd"], "%s: handed-over files and link unchanged" % n)
        v2 = helper(image, folder, "if test -d /d/v2; then echo yes; fi").stdout.strip()
        check(v2 == "yes", "%s: agent created its v2 state" % n)
    finally:
        docker("rm", "-f", name, check_rc=False)
        cleanup(image, folder)


HARDENED = ["--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID", "--security-opt", "no-new-privileges"]

REFUSED = [
    ("PUID=0", ["-e", "PUID=0"]),
    ("PGID=0", ["-e", "PGID=0"]),
    ("PUID=00", ["-e", "PUID=00"]),
    ("PGID=000", ["-e", "PGID=000"]),
    ("PUID=-1", ["-e", "PUID=-1"]),
    ("PUID=abc", ["-e", "PUID=abc"]),
    ("PGID=1e3", ["-e", "PGID=1e3"]),
    ("PUID=0100", ["-e", "PUID=0100"]),
    ("PUID=4294967295", ["-e", "PUID=4294967295"]),
    ("PUID=4294967296 (wraps to 0)", ["-e", "PUID=4294967296"]),
    ("PGID=4294967296 (wraps to 0)", ["-e", "PGID=4294967296"]),
    ("PUID=18446744073709551616", ["-e", "PUID=18446744073709551616"]),
    ("--user 1000:0", ["--user", "1000:0"]),
    ("--user 1000 --group-add 0", ["--user", "1000:1000", "--group-add", "0"]),
]

# Checked on a writable root, where nothing else would stop the handover.
DATA_DIRS = ["/", "/etc", "/app", "/usr", "/var/lib/seawise", "/run/seawise", "/tmp/seawise", "/home/seawise",
             "/srv/seawise", "/config/../usr", "/config/./x", "/configx", "/datax", "config"]


# Another app's data, as when a parent folder is mapped by mistake.
FOREIGN = """set -e
mkdir -p /d/otherapp
echo db > /d/otherapp/db.sqlite
chmod 600 /d/otherapp/db.sqlite
chown -R 0:0 /d
"""


def refusals(image):
    print("entrypoint refusals")
    folder = tempfile.mkdtemp(prefix=PREFIX)
    try:
        cases = [(d, HARDENED + a, "") for d, a in REFUSED]
        cases += [("SEAWISE_DATA_DIR=" + d, ["-e", "SEAWISE_DATA_DIR=" + d, "-e", "PUID=99", "-e", "PGID=100"], "") for d in DATA_DIRS]
        cases.append(("root start without CHOWN/SETUID/SETGID", ["--read-only", "--cap-drop", "ALL", "-e", "PUID=99", "-e", "PGID=100"], ""))
        cases.append(("a non-empty folder without SeaWise state", ["-e", "PUID=99", "-e", "PGID=100"], FOREIGN))
        for desc, extra, seed in cases:
            helper(image, folder, "rm -rf /d/* /d/.[!.]*; chown 1000:1000 /d; chmod 755 /d")
            if seed:
                helper(image, folder, seed)
            p = docker("run", "--rm", "--name", PREFIX + "refuse", "--network", "none", "-v", folder + ":/config", *extra, image, check_rc=False, timeout=30)
            docker("rm", "-f", PREFIX + "refuse", check_rc=False)
            refused = re.search(r"^ERROR: ", p.stderr, re.M)
            if not check(p.returncode not in (0, 124) and refused, "refuses %s" % desc):
                print("        exit %d: %s" % (p.returncode, (p.stdout + p.stderr).strip()[-500:]))
            v2 = helper(image, folder, "if test -e /d/v2; then echo ran; fi").stdout.strip()
            check(v2 != "ran", "agent did not start for %s" % desc)
            if seed:
                left = helper(image, folder, "find /d ! -user 0 ! -path /d").stdout.split()
                check(not left, "nothing in the folder changed owner %s" % (left or ""))
    finally:
        docker("rm", "-f", PREFIX + "refuse", check_rc=False)
        cleanup(image, folder)


def default_run(image):
    """Plain docker run with no hardening flags: still never root."""
    t = Template("default")
    t.env = {"PUID": "99", "PGID": "100"}
    t.volumes = ["/config"]
    run_template(t, image)
    print("empty root-owned data folder, writable root")
    t.name = "empty"
    run_template(t, image, seed="chown 0:0 /d && chmod 755 /d")


def nested_mounts(image):
    """Mounts inside the data folder are not handed over, whatever their device."""
    print("nested mounts")
    name = PREFIX + "nested"
    folder = tempfile.mkdtemp(prefix=PREFIX)
    inner = tempfile.mkdtemp(prefix=PREFIX)
    try:
        helper(image, folder, SEED)
        helper(image, inner, "echo x > /d/f && chmod 600 /d/f && chown -R 0:0 /d")
        docker("run", "-d", "--name", name, "--network", "none", "--health-interval", "2s",
               "-e", "PUID=99", "-e", "PGID=100", "-v", folder + ":/config",
               "-v", inner + ":/config/bind [x]*", "--tmpfs", "/config/tmpfs", image)
        if check(wait_healthy(name), "nested: healthy"):
            left = helper(image, inner, "find /d -user 0").stdout.split()
            check(left == ["/d", "/d/f"], "nested: bind mount with glob characters in its name left alone %s" % left)
            tm = docker("exec", name, "stat", "-c", "%u", "/config/tmpfs").stdout.strip()
            check(tm == "0", "nested: tmpfs mount (-xdev) left alone")
            rest = helper(image, folder, "find /d -user 0 ! -path '/d/bind \\[x\\]\\*' ! -path /d/tmpfs").stdout.split()
            check(not rest, "nested: the rest was handed over %s" % rest)
            check("WARNING" not in docker("logs", name).stderr, "nested: no handover warnings")
    finally:
        docker("rm", "-f", name, check_rc=False)
        cleanup(image, folder)
        cleanup(image, inner)


def image_files(image):
    """setuid/setgid files and files with security.capability xattrs, from
    the exported filesystem (PAX headers carry xattrs)."""
    cid = docker("create", "--name", PREFIX + "export", image).stdout.strip()
    try:
        with tempfile.TemporaryFile() as f:
            subprocess.run(["docker", "export", cid], stdout=f, check=True, timeout=300)
            f.seek(0)
            suid, fcaps = [], []
            with tarfile.open(fileobj=f) as tar:
                for m in tar:
                    if m.isfile() and m.mode & 0o6000:
                        suid.append(m.name)
                    if any("security.capability" in k for k in m.pax_headers):
                        fcaps.append(m.name)
            return suid, fcaps
    finally:
        docker("rm", "-f", cid, check_rc=False)


def image_checks(image):
    print("image")
    cfg = json.loads(docker("inspect", image).stdout)[0]["Config"]
    hc = cfg.get("Healthcheck") or {}
    check("/healthz" in " ".join(hc.get("Test") or []), "healthcheck probes /healthz")
    check(cfg.get("User", "") in ("", "0", "root"), "starts as root only to drop to PUID/PGID (User=%r)" % cfg.get("User"))
    check((cfg.get("Labels") or {}).get("io.seawise.line") == "2", "labelled as line 2")
    check("8082/tcp" in (cfg.get("ExposedPorts") or {}), "exposes 8082")
    check(cfg.get("Env") and "SEAWISE_DATA_DIR=/config" in cfg["Env"], "data folder is /config")
    out = docker("run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c",
                 "find /app ! -user 0 -o -perm -0002 ! -type l; echo --;"
                 "find / -xdev -perm -0002 -type d ! -path /tmp ! -path /var/tmp; echo --").stdout
    app, ww = (s.split() for s in out.split("--")[:2])
    suid, fcaps = image_files(image)
    check(not suid, "no setuid or setgid files %s" % (suid or ""))
    check(not fcaps, "no files with capability xattrs %s" % (fcaps or ""))
    check(not app, "/app is root-owned and not world-writable %s" % (app or ""))
    check(not ww, "no world-writable folders besides /tmp %s" % (ww or ""))


def readme_example():
    print("README")
    text = open(os.path.join(HERE, "README.md"), encoding="utf-8").read()
    ports = re.findall(r"(?:^|\s)-p (\S+:\S+)", text, re.M)
    check(ports and all(p.startswith("127.0.0.1:") for p in ports), "docker run example publishes on 127.0.0.1 only %s" % ports)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    image = sys.argv[1]
    templates = [
        ("compose", load_compose, "compose/docker-compose.yml"),
        ("synology", load_compose, "synology/docker-compose.yml"),
        ("truenas", load_compose, "truenas/docker-compose.yml"),
        ("unraid", load_unraid, "unraid/seawise.xml"),
        ("homeassistant", load_homeassistant, "homeassistant/config.yaml"),
    ]
    image_checks(image)
    for name, load, path in templates:
        print(name)
        t = load(name, os.path.join(HERE, path))
        static_checks(t)
        run_template(t, image)
    print("default docker run")
    default_run(image)
    nested_mounts(image)
    readme_example()
    refusals(image)
    if failures:
        print("\n%d check(s) failed" % len(failures))
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main()
