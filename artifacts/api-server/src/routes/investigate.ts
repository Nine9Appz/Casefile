import { runInvestigation } from "@workspace/sift-agent";
import { Router, type IRouter } from "express";

const router: IRouter = Router();

router.post("/cases/:caseId/investigate", async (req, res) => {
  const { caseId } = req.params;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  let cancelled = false;
  req.on("close", () => {
    cancelled = true;
  });

  const send = (event: string, data: unknown) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    for await (const ev of runInvestigation({
      caseId,
      isCancelled: () => cancelled,
    })) {
      send(ev.type, ev);
      if (cancelled) break;
    }
  } catch (err) {
    req.log.error({ err, caseId }, "investigation stream crashed");
    send("error", {
      type: "error",
      message: err instanceof Error ? err.message : String(err),
      fatal: true,
    });
    send("done", { type: "done", reason: "error" });
  } finally {
    res.end();
  }
});

export default router;
