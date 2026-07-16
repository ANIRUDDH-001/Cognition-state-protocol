"""Live UI server -- Doc 5 §3.  `python -m ui.server` then open http://127.0.0.1:8000

The UI is a SUBSCRIBER, not a component. It renders `demo.run_demo.run()` -- the
exact code path the terminal demo and the tests exercise -- via the `on_event`
hook, plus `Telemetry.on_record`. Pull the UI out and the fabric behaves
identically; it is not in the trust path and it cannot vote, sign, or promote
anything. That is the whole reason it was safe to add this late.

The demo loop is synchronous and CPU-cheap (time is virtual: a 30-task run with a
1800 ms/hop lossy link finishes in milliseconds), so it runs on a worker thread
and hands events to the event loop. `--pace` makes it watchable. Pacing is
presentation, never physics -- the numbers come from the virtual clock and do not
move when you slow the narration down.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import queue
import threading

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from chaos import inject
from demo.run_demo import fabric_event, run

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "static", "index.html")

# Per-message latency is ~6 records per negotiation x 60 negotiations. The UI
# wants the beats, not the firehose; task events already carry their own p95.
FORWARD_METRICS = {"slo.breach", "fabric.deny.count", "fabric.revoke", "fabric.insight.applied"}


class Hub:
    """Fan-out to connected browsers, plus a replay buffer so a late tab catches up."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.history: list[dict] = []
        self.loop: asyncio.AbstractEventLoop | None = None
        self.q: queue.Queue = queue.Queue()

    def publish(self, msg: dict) -> None:
        """Called from the demo worker thread. Never blocks it, never raises into it."""
        self.history.append(msg)
        del self.history[:-4000]
        self.q.put(msg)

    def reset(self) -> None:
        """Clear the replay buffer when a NEW run is requested -- not on `run_start`,
        which the fabric-on run emits only after the baseline has already been
        published, and would therefore erase the very comparison it needs."""
        self.history = []

    async def pump(self) -> None:
        """Drain the worker's queue on the event loop and fan out."""
        while True:
            try:
                msg = self.q.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.02)
                continue
            for ws in list(self.clients):
                try:
                    await ws.send_json(msg)
                except Exception:
                    self.clients.discard(ws)


hub = Hub()


@asynccontextmanager
async def lifespan(_app):
    hub.loop = asyncio.get_running_loop()
    pump = asyncio.create_task(hub.pump())
    yield
    pump.cancel()


app = FastAPI(title="Cognition Fabric", lifespan=lifespan)
STATE: dict = {"mesh": None, "running": False, "thread": None}


def _on_record(rec: dict) -> None:
    """Telemetry subscriber (Doc 5 §3.1) -- one hook, whole event stream."""
    if rec.get("kind") == "event" or rec.get("name") in FORWARD_METRICS:
        hub.publish({"type": "telemetry", "name": rec.get("name"),
                     "kind": rec.get("kind"), "attrs": rec.get("attrs", {})})


def _run_demo(seed: int, fabric_on: bool, analyzer: str, pace: float, out_dir: str) -> None:
    try:
        # The baseline first, quietly: same seed, pipeline off. It is what the
        # rounds comparison is measured against, and it costs nothing to run.
        _bm, base_rows, _ = run(seed, False, quiet=True,
                                out_dir=os.path.join(out_dir, "baseline"))
        hub.publish({"type": "baseline",
                     "rounds": [{"idx": r["task"].idx, "rounds": r["result"].rounds,
                                 "aborted": r["result"].aborted,
                                 "duration_ms": round(r["result"].duration_ms, 1)}
                                for r in base_rows]})

        mesh, _rows, _marks = run(seed, fabric_on, quiet=True, out_dir=out_dir,
                                  pace=pace, analyzer=analyzer, on_event=hub.publish,
                                  on_record=_on_record)
        STATE["mesh"] = mesh
    except Exception as e:  # a crashed run must say so, not hang the page
        hub.publish({"type": "error", "detail": f"{type(e).__name__}: {e}"})
    finally:
        STATE["running"] = False
        hub.publish({"type": "idle"})


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(INDEX)


@app.get("/state")
async def state() -> JSONResponse:
    return JSONResponse({"running": STATE["running"], "history": hub.history})


@app.post("/run")
async def start(seed: int = 42, fabric: str = "on", analyzer: str = "rules",
                pace: float = 0.25, out: str = "out/ui") -> JSONResponse:
    if STATE["running"]:
        return JSONResponse({"ok": False, "detail": "already running"}, status_code=409)
    STATE["running"] = True
    STATE["mesh"] = None
    hub.reset()
    t = threading.Thread(target=_run_demo, daemon=True,
                         args=(seed, fabric == "on", analyzer, pace, out))
    STATE["thread"] = t
    t.start()
    return JSONResponse({"ok": True})


@app.post("/chaos/{fault}")
async def chaos(fault: str) -> JSONResponse:
    """Fire a fault at the LIVE mesh. This is the judge-facing button."""
    mesh = STATE["mesh"]
    if mesh is None:
        return JSONResponse(
            {"ok": False, "detail": "no finished run yet -- press Run and let it complete"},
            status_code=409)
    fn = {"f1": inject.f1_node_down, "f2": inject.f2_poisoned, "f3": inject.f3_partition}.get(fault)
    if fn is None:
        return JSONResponse({"ok": False, "detail": f"unknown fault {fault}"}, status_code=404)

    def work() -> None:
        try:
            rep = fn(mesh)
            hub.publish({"type": "chaos", "fault": fault, "report": _jsonable(rep)})
            hub.publish(fabric_event(mesh))
        except Exception as e:
            hub.publish({"type": "error", "detail": f"chaos {fault}: {e}"})

    threading.Thread(target=work, daemon=True).start()
    return JSONResponse({"ok": True})


def _jsonable(o):
    """Chaos reports carry sets/tuples/frozensets from the fault model."""
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in o]
    if isinstance(o, (str, int, float, bool)) or o is None:
        return o
    return str(o)


@app.websocket("/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    hub.clients.add(ws)
    try:
        for msg in list(hub.history):  # catch a late-joining tab up
            await ws.send_json(msg)
        while True:
            await ws.receive_text()  # client never sends; this just parks
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        hub.clients.discard(ws)


def main(argv=None) -> int:
    import uvicorn
    ap = argparse.ArgumentParser(description="Cognition Fabric live UI")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    print(f"  Cognition Fabric UI -> http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
