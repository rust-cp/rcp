#!/usr/bin/env python3
"""A stand-in OCI registry: the Distribution API v2 over plain HTTP, in memory, with the
token dance when started with --token and basic credentials when started with --user.
It counts blob uploads and manifest pushes and reports them on GET /_stub/stats, so a
test can prove a second mirror moved nothing.

Usage: registry_stub.py PORT [--token] [--user NAME:PASS] [--seed DIR]

--seed loads an OCI image layout directory (oci-layout, index.json, blobs/) into the
repository named by its index's ref annotations' "repo" prefix (see seed()).
"""
import base64
import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOBS = {}          # digest -> bytes (shared across repositories, like a real registry)
MANIFESTS = {}      # (repo, digest) -> (media type, bytes)
TAGS = {}           # repo -> {tag: digest}
GHOSTS = {}         # repo -> tags the listing names that no longer resolve (see /_stub/ghost)
UPLOADS = {}        # uuid -> bytearray
CUT = set()            # blobs whose stream --cut has already killed once
STATS = {"blob_uploads": 0, "manifest_pushes": 0, "mounts": 0, "blob_heads": 0, "away_uploads": 0, "away_authorized": 0, "away_port": 0, "cuts": 0, "blob_gets": 0, "dropped": 0}
LOCK = threading.Lock()
TOKEN = "stub-token-1234"
OPTS = {"token": False, "user": None, "away": None, "expire": 0, "throttle": False, "no_manifests": False, "cut": 0, "norange": False, "realm": None, "liesrange": False, "always": False, "blobstatus": 0, "drophead": 0}
ISSUED = {"n": 0}      # tokens handed out, so --expire can retire the older ones


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body=b"", headers=None, ctype="application/json"):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if body or code != 204:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def error(self, code, name, msg=""):
        self.reply(code, json.dumps({"errors": [{"code": name, "message": msg}]}).encode())

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def authorized(self):
        auth = self.headers.get("Authorization", "")
        if OPTS["token"]:
            # --expire N retires the FIRST token once N requests have used it, which is
            # what a real token's lifetime looks like from the client's side: the call that
            # was authorized a moment ago is now a 401. Once only, and deliberately: a
            # token that keeps dying races the workers that are renewing it, and the
            # property under test is that an expiry is survived, not how often.
            if auth.startswith("Bearer "):
                with LOCK:
                    live = auth[7:] == TOKEN + "-%d" % ISSUED["n"]
                    # counted on blob reads only, so the expiry lands on the streaming GET
                    # rather than on a buffered request that would renew it in passing
                    if live and OPTS["expire"] and ISSUED["n"] == 0 and "/blobs/sha256:" in self.path:
                        STATS["token_uses"] = STATS.get("token_uses", 0) + 1
                        if STATS["token_uses"] >= OPTS["expire"]:
                            ISSUED["n"] = 1       # the first token is dead from here on
                if live:
                    return True
            # --realm URL points the challenge at ANOTHER host, which is what a hostile
            # or compromised registry does: the client is told where to go for a token,
            # and it carries the credentials there.
            where = OPTS["realm"] or ("http://127.0.0.1:%d/token" % self.server.server_address[1])
            self.reply(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', {"WWW-Authenticate": 'Bearer realm="%s",service="stub",scope="repository:x:pull,push"' % where})
            return False
        if OPTS["user"]:
            want = "Basic " + base64.b64encode(OPTS["user"].encode()).decode()
            if auth == want:
                return True
            self.reply(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', {"WWW-Authenticate": 'Basic realm="stub"'})
            return False
        return True

    def throttled(self):
        """--throttle answers every blob GET with 429, the way a registry over its rate
        limit does. It is the one failure worth waiting on, so it must not arrive as the
        same code as a missing repository.

        --blobstatus N answers every blob GET with N instead, which is what makes the
        429 arm's control a control: without a second status to compare against, "429
        becomes busy" is measured by an arm whose companion run uses no status at all, and
        reverting the mapping leaves that companion green."""
        if OPTS["blobstatus"] and "/blobs/" in self.path:
            self.reply(OPTS["blobstatus"], b'{"errors":[{"code":"STUBBED"}]}')
            return True
        if OPTS["throttle"] and "/blobs/" in self.path:
            self.reply(429, b'{"errors":[{"code":"TOOMANYREQUESTS"}]}', {"Retry-After": "1"})
            return True
        return False

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/_stub/publish":
            # the test turns publishing back on, so a retry can be measured against the
            # same registry -- and the same blobs -- that refused it
            OPTS["no_manifests"] = False
            return self.reply(200, b"ok")
        # /_stub/vanish/<repo>/<digest>: the manifest goes and nothing else does -- no tag
        # moves, no index that names it changes. An interrupted delete leaves exactly this
        # (the child went, its index had not yet), and so does a delete on another
        # connection caught between two reads.
        m = re.match(r"^/_stub/vanish/(.+)/(sha256:[0-9a-f]+)$", path)
        if m:
            with LOCK:
                MANIFESTS.pop((m.group(1), m.group(2)), None)
            return self.reply(200, b"ok")
        # /_stub/ghost/<repo>/<tag>: the listing names a tag that no longer resolves, which
        # is what a reader sees when the tag is deleted between the listing and its GET.
        m = re.match(r"^/_stub/ghost/(.+)/([^/]+)$", path)
        if m:
            with LOCK:
                GHOSTS.setdefault(m.group(1), set()).add(m.group(2))
            return self.reply(200, b"ok")
        if path == "/_stub/stats":
            with LOCK:
                return self.reply(200, json.dumps(STATS).encode())
        if path == "/token":
            # the token endpoint takes the basic credentials when a user is configured
            if OPTS["user"]:
                want = "Basic " + base64.b64encode(OPTS["user"].encode()).decode()
                if self.headers.get("Authorization", "") != want:
                    return self.reply(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}')
            with LOCK:
                STATS["tokens_issued"] = STATS.get("tokens_issued", 0) + 1
                current = TOKEN + "-%d" % ISSUED["n"]
            return self.reply(200, json.dumps({"token": current, "access_token": current}).encode())
        if not self.authorized():
            return
        if self.throttled():
            return
        if path == "/v2/" or path == "/v2":
            return self.reply(200, b"{}", {"Docker-Distribution-API-Version": "registry/2.0"})
        m = re.match(r"^/v2/(.+)/tags/list$", path)
        if m:
            repo = m.group(1)
            with LOCK:
                known = repo in TAGS or any(r == repo for (r, _) in MANIFESTS)
                tags = sorted(set(TAGS.get(repo, {}).keys()) | GHOSTS.get(repo, set()))
            if not known:
                # a real registry answers NAME_UNKNOWN for a repository it has never seen
                return self.error(404, "NAME_UNKNOWN", repo)
            return self.reply(200, json.dumps({"name": repo, "tags": tags}).encode())
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", path)
        if m:
            repo, ref = m.group(1), m.group(2)
            with LOCK:
                digest = ref if ref.startswith("sha256:") else TAGS.get(repo, {}).get(ref)
                entry = MANIFESTS.get((repo, digest)) if digest else None
            if not entry:
                return self.error(404, "MANIFEST_UNKNOWN", ref)
            ctype, data = entry
            return self.reply(200, data, {"Docker-Content-Digest": digest}, ctype)
        m = re.match(r"^/v2/(.+)/blobs/(sha256:[0-9a-f]+)$", path)
        if m:
            repo, digest = m.group(1), m.group(2)
            with LOCK:
                data = BLOBS.get(digest)
                if self.command == "HEAD":
                    STATS["blob_heads"] += 1
            if data is None:
                return self.error(404, "BLOB_UNKNOWN", digest)
            # --drophead N: every Nth blob GET is read and then the connection is closed
            # with NO response. That is what a client sees when it reuses a keep-alive
            # connection the server has already closed while it sat idle -- EOF before the
            # status line -- and it is the one failure a GET can meet before any of its
            # body is read, so reissuing it costs nothing.
            if OPTS["drophead"] and self.command == "GET":
                with LOCK:
                    STATS["blob_gets"] += 1
                    drop = STATS["blob_gets"] % OPTS["drophead"] == 0
                    if drop:
                        STATS["dropped"] += 1
                if drop:
                    self.close_connection = True
                    return
            rng = None if OPTS["norange"] else self.headers.get("Range")
            # --liesrange answers 206 -- the status a client checks -- while sending the
            # WHOLE blob from byte zero and saying so in Content-Range. A client that
            # trusts the status and not the header mis-assembles the read.
            if OPTS["liesrange"] and rng:
                return self.reply(206, data, {"Content-Range": "bytes 0-%d/%d" % (len(data) - 1, len(data)), "Docker-Content-Digest": digest}, "application/octet-stream")
            # --cut N: answer with the real Content-Length, send N bytes from wherever
            # the read was asked to start, and hang up. That is what a token expiring
            # mid-body looks like to a client -- the 200 and its headers are already
            # spent, so there is no 401 left to read, only a stream that stops.
            #
            # This sits BEFORE the honest Range branch on purpose, so a RESUMED read can
            # be cut too. It did not, at first, and the one-shot `--always` measurement
            # built on it was worthless: every resume carried a Range, took the branch
            # below, and was served in full, so a stub that was meant to cut a thousand
            # times cut exactly once.
            if OPTS["cut"] and self.command == "GET" and len(data) > OPTS["cut"]:
                # --always keeps cutting: every GET of this blob delivers `cut` bytes from
                # wherever it was asked and hangs up, so a client that resumes has to do it
                # once per chunk. That is the case a one-shot cut cannot reach, and it is
                # what tells a resume LOOP from a resume RECURSION.
                with LOCK:
                    first = OPTS["always"] or digest not in CUT
                    if first:
                        CUT.add(digest)
                        STATS["cuts"] = STATS.get("cuts", 0) + 1
                if first:
                    at = 0
                    if rng and rng.startswith("bytes="):
                        at = int(rng[6:].split("-")[0])
                    body = data[at:]
                    if at:
                        self.send_response(206)
                        self.send_header("Content-Range", "bytes %d-%d/%d" % (at, len(data) - 1, len(data)))
                    else:
                        self.send_response(200)
                    self.send_header("Docker-Content-Digest", digest)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body[: OPTS["cut"]])
                    self.wfile.flush()
                    self.close_connection = True
                    return
            if rng and rng.startswith("bytes="):
                a, b = rng[6:].split("-")
                a = int(a)
                b = int(b) if b else len(data) - 1
                part = data[a : b + 1]
                return self.reply(206, part, {"Content-Range": "bytes %d-%d/%d" % (a, b, len(data)), "Docker-Content-Digest": digest}, "application/octet-stream")
            return self.reply(200, data, {"Docker-Content-Digest": digest}, "application/octet-stream")
        return self.error(404, "NOT_FOUND", path)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""
        if not self.authorized():
            return
        m = re.match(r"^/v2/(.+)/blobs/uploads/$", path)
        if m:
            repo = m.group(1)
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            if "mount" in params:
                # cross-repository mount: the blob exists, so it is here already
                with LOCK:
                    known = params["mount"] in BLOBS
                    if known:
                        STATS["mounts"] += 1
                if known:
                    return self.reply(201, b"", {"Location": "/v2/%s/blobs/%s" % (repo, params["mount"]), "Docker-Content-Digest": params["mount"]})
            if "digest" in params:
                # monolithic upload in one POST
                data = self.body()
                if digest_of(data) != params["digest"]:
                    return self.error(400, "DIGEST_INVALID")
                with LOCK:
                    BLOBS[params["digest"]] = data
                    STATS["blob_uploads"] += 1
                return self.reply(201, b"", {"Location": "/v2/%s/blobs/%s" % (repo, params["digest"]), "Docker-Content-Digest": params["digest"]})
            uuid = hashlib.sha256(os.urandom(16)).hexdigest()[:32]
            with LOCK:
                UPLOADS[uuid] = bytearray()
            self.body()
            # a registry may hand the upload to another host entirely (ECR and GAR sign a
            # URL on their storage); --away makes this stub do it, on a second listener
            where = "/v2/%s/blobs/uploads/%s" % (repo, uuid)
            if OPTS["away"]:
                where = "http://127.0.0.1:%d%s" % (OPTS["away"], where)
            return self.reply(202, b"", {"Location": where, "Docker-Upload-UUID": uuid, "Range": "0-0"})
        return self.error(404, "NOT_FOUND", path)

    def do_PATCH(self):
        path = self.path.split("?")[0]
        if not self.authorized():
            return
        m = re.match(r"^/v2/(.+)/blobs/uploads/([0-9a-f]+)$", path)
        if m:
            repo, uuid = m.group(1), m.group(2)
            data = self.body()
            with LOCK:
                if uuid not in UPLOADS:
                    return self.error(404, "BLOB_UPLOAD_UNKNOWN")
                UPLOADS[uuid].extend(data)
                n = len(UPLOADS[uuid])
            return self.reply(202, b"", {"Location": "/v2/%s/blobs/uploads/%s" % (repo, uuid), "Docker-Upload-UUID": uuid, "Range": "0-%d" % max(n - 1, 0)})
        return self.error(404, "NOT_FOUND", path)

    def do_PUT(self):
        path = self.path.split("?")[0]
        query = self.path.split("?")[1] if "?" in self.path else ""
        if not self.authorized():
            return
        m = re.match(r"^/v2/(.+)/blobs/uploads/([0-9a-f]+)$", path)
        if m:
            repo, uuid = m.group(1), m.group(2)
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            data = self.body()
            with LOCK:
                if uuid not in UPLOADS:
                    return self.error(404, "BLOB_UPLOAD_UNKNOWN")
                whole = bytes(UPLOADS.pop(uuid)) + data
            if digest_of(whole) != params.get("digest"):
                return self.error(400, "DIGEST_INVALID", "%s is not %s" % (digest_of(whole), params.get("digest")))
            with LOCK:
                BLOBS[params["digest"]] = whole
                STATS["blob_uploads"] += 1
            return self.reply(201, b"", {"Location": "/v2/%s/blobs/%s" % (repo, params["digest"]), "Docker-Content-Digest": params["digest"]})
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", path)
        if m:
            repo, ref = m.group(1), m.group(2)
            data = self.body()
            # --no-manifests N refuses the first N publishes while taking every blob,
            # which is the shape of a copy that dies between the two: blobs up, image
            # absent. After N it publishes, so a retry can be measured.
            if OPTS["no_manifests"]:
                return self.error(500, "UNKNOWN", "this registry is not publishing today")
            ctype = self.headers.get("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            try:
                doc = json.loads(data)
            except ValueError:
                return self.error(400, "MANIFEST_INVALID")
            digest = digest_of(data)
            if ref.startswith("sha256:") and ref != digest:
                return self.error(400, "DIGEST_INVALID")
            # every blob a manifest names must be here already
            refs = [l["digest"] for l in doc.get("layers", [])] + ([doc["config"]["digest"]] if "config" in doc else [])
            with LOCK:
                missing = [d for d in refs if d not in BLOBS]
                for child in doc.get("manifests", []):
                    if (repo, child["digest"]) not in MANIFESTS:
                        missing.append(child["digest"])
            if missing:
                return self.error(400, "MANIFEST_BLOB_UNKNOWN", ",".join(missing))
            with LOCK:
                MANIFESTS[(repo, digest)] = (ctype, data)
                if not ref.startswith("sha256:"):
                    TAGS.setdefault(repo, {})[ref] = digest
                STATS["manifest_pushes"] += 1
            return self.reply(201, b"", {"Location": "/v2/%s/manifests/%s" % (repo, digest), "Docker-Content-Digest": digest})
        return self.error(404, "NOT_FOUND", path)

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if not self.authorized():
            return
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", path)
        if m:
            repo, ref = m.group(1), m.group(2)
            with LOCK:
                if ref.startswith("sha256:"):
                    # a digest that names no manifest is MANIFEST_UNKNOWN, as a real registry
                    # answers -- the client asks this way when it cannot tell a manifest from
                    # a blob, and a 202 here would call every blob a deleted manifest
                    if (repo, ref) not in MANIFESTS:
                        return self.error(404, "MANIFEST_UNKNOWN", path)
                    MANIFESTS.pop((repo, ref), None)
                    for t, d in list(TAGS.get(repo, {}).items()):
                        if d == ref:
                            del TAGS[repo][t]
                else:
                    TAGS.get(repo, {}).pop(ref, None)
            return self.reply(202, b"")
        # A blob DELETE that the registry declines. Docker Hub, ECR and Artifact
        # Registry all answer 405 here: blobs are the garbage collector's business,
        # not the client's. rcp counted that as a removal, which is the defect the
        # `blob_delete_refused` counter exists to measure.
        if re.match(r"^/v2/(.+)/blobs/([^/]+)$", path):
            with LOCK:
                STATS["blob_delete_refused"] = STATS.get("blob_delete_refused", 0) + 1
            return self.error(405, "UNSUPPORTED", path)
        return self.error(404, "NOT_FOUND", path)


def seed(repo, layout):
    """Loads an OCI image layout directory into `repo`: every blob, every manifest the
    index names (and their children), the tags from ref.name annotations."""
    with open(os.path.join(layout, "index.json")) as f:
        index = json.load(f)
    blobs = os.path.join(layout, "blobs", "sha256")
    for name in os.listdir(blobs):
        with open(os.path.join(blobs, name), "rb") as f:
            BLOBS["sha256:" + name] = f.read()

    def manifest(digest):
        data = BLOBS[digest]
        doc = json.loads(data)
        for child in doc.get("manifests", []):
            manifest(child["digest"])
        MANIFESTS[(repo, digest)] = (doc.get("mediaType", "application/vnd.oci.image.manifest.v1+json"), data)

    for m in index.get("manifests", []):
        manifest(m["digest"])
        tag = (m.get("annotations") or {}).get("org.opencontainers.image.ref.name")
        if tag:
            TAGS.setdefault(repo, {})[tag] = m["digest"]


class AwayHandler(Handler):
    """The storage host an upload can be handed to. A signed URL carries its own
    credential, so this one wants no Authorization -- and records whether it was sent
    one anyway, which would mean the registry's token had leaked to a third party."""

    def authorized(self):
        with LOCK:
            STATS["away_uploads"] += 1
            if self.headers.get("authorization"):
                STATS["away_authorized"] += 1
        return True


def main():
    port = int(sys.argv[1])
    args = sys.argv[2:]
    while args:
        a = args.pop(0)
        if a == "--token":
            OPTS["token"] = True
        elif a == "--user":
            OPTS["user"] = args.pop(0)
        elif a == "--no-manifests":
            OPTS["no_manifests"] = True
        elif a == "--throttle":
            OPTS["throttle"] = True
        elif a == "--blobstatus":
            OPTS["blobstatus"] = int(args.pop(0))
        elif a == "--always":
            OPTS["always"] = True
        elif a == "--liesrange":
            OPTS["liesrange"] = True
        elif a == "--realm":
            OPTS["realm"] = args.pop(0)
        elif a == "--norange":
            OPTS["norange"] = True
        elif a == "--drophead":
            OPTS["drophead"] = int(args.pop(0))
        elif a == "--cut":
            OPTS["cut"] = int(args.pop(0))
        elif a == "--expire":
            OPTS["expire"] = int(args.pop(0))
        elif a == "--away":
            OPTS["away"] = True
        elif a == "--seed":
            repo = args.pop(0)
            seed(repo, args.pop(0))
        else:
            raise SystemExit("unknown option " + a)
    if OPTS["away"]:
        away = ThreadingHTTPServer(("127.0.0.1", 0), AwayHandler)
        OPTS["away"] = away.server_address[1]
        # reported through the stats so a test can name the away host in a rail: the
        # port is picked here, and a run that must be told where it may hand blobs on
        # to needs to know it
        STATS["away_port"] = OPTS["away"]
        threading.Thread(target=away.serve_forever, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stdout.write("ready %d\n" % server.server_address[1])
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
