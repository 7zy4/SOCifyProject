"""Observe Chromium requests by document identity, including navigation races."""

import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class PendingRequest:
    identifier: str
    url: str
    method: str
    resource_type: str
    frame: str
    loader: str


class DocumentRequests:
    def __init__(self, page, session=None):
        self.session = session if session is not None else page.context.new_cdp_session(page)
        self.pending = {}
        self.loaders = {}
        self.retired_loaders = set()
        self.retirements = []
        self.events = deque(maxlen=300)
        self.last_request = time.monotonic()
        self.session.on("Network.requestWillBeSent", self.started)
        self.session.on("Network.loadingFinished", self.finished)
        self.session.on("Network.loadingFailed", self.finished)
        self.session.on("Page.frameNavigated", self.committed)
        self.session.on("Page.frameDetached", self.detached)
        self.session.send("Page.enable")
        self.session.send("Network.enable")
        self.remember(self.session.send("Page.getFrameTree")["frameTree"])

    def remember(self, tree):
        frame = tree["frame"]
        self.loaders[frame["id"]] = frame.get("loaderId", "")
        for child in tree.get("childFrames", []):
            self.remember(child)

    def started(self, event):
        request = event["request"]
        item = PendingRequest(event["requestId"], request["url"], request["method"], event.get("type", "Other"), event.get("frameId", ""), event["loaderId"])
        self.events.append({"event": "start", "id": item.identifier, "path": urlsplit(item.url).path, "frame": item.frame, "loader": item.loader})
        # A late delivery from a positively retired document must not revive it.
        # Unknown loaders (including workers) are retained, never guessed away.
        if not item.loader or (item.frame, item.loader) not in self.retired_loaders:
            self.pending[item.identifier] = item
        self.last_request = time.monotonic()

    def finished(self, event):
        self.pending.pop(event["requestId"], None)
        self.events.append({"event": "finish", "id": event["requestId"], "error": event.get("errorText")})
        self.last_request = time.monotonic()

    def retire(self, frame, loader):
        if not loader:
            return
        self.retired_loaders.add((frame, loader))
        retired = [item for item in self.pending.values() if item.frame == frame and item.loader == loader]
        if retired:
            self.retirements.append(sorted(urlsplit(item.url).path for item in retired))
        for item in retired:
            self.pending.pop(item.identifier)

    def committed(self, event):
        frame = event["frame"]
        identifier, loader = frame["id"], frame.get("loaderId", "")
        previous = self.loaders.get(identifier)
        if previous and previous != loader:
            self.retire(identifier, previous)
        self.retired_loaders.discard((identifier, loader))
        self.loaders[identifier] = loader
        self.events.append({"event": "commit", "frame": identifier, "loader": loader, "previous": previous})
        self.last_request = time.monotonic()

    def detached(self, event):
        # A process swap can keep the document alive in another target.
        if event.get("reason") == "remove":
            self.retire(event["frameId"], self.loaders.pop(event["frameId"], ""))

    def diagnostics(self):
        return {
            "events": list(self.events),
            "pending": [
                {
                    "id": item.identifier,
                    "path": urlsplit(item.url).path,
                    "method": item.method,
                    "type": item.resource_type,
                    "frame": item.frame,
                    "loader": item.loader,
                }
                for item in self.pending.values()
            ],
        }
