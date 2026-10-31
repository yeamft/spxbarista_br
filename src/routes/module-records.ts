import { Router } from "express";
import { z } from "zod";
import type { Server as SocketServer } from "socket.io";
import { ModuleRecord } from "../models/ModuleRecord.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { asyncHandler } from "../lib/async-handler.js";
import { listShifts } from "./barista.js";

/** Duty board lives in BaristaShift (barista-only); never serve or store a client copy. */
const BARISTA_AVAILABILITY_KEY = "barista_availability";

async function baristaAvailabilityRows() {
  const shifts = await listShifts();
  return shifts.map((shift, position) => ({
    recordId: shift.id,
    data: shift,
    position,
    updatedAt: shift.updatedAt,
  }));
}

export function createModuleRecordsRouter(io: SocketServer) {
  const router = Router();

  router.get("/:key", requireAuth, asyncHandler(async (req: AuthedRequest, res) => {
    const moduleKey = String(req.params.key || "").trim();
    if (!moduleKey) {
      res.status(400).json({ error: "Module key is required" });
      return;
    }

    if (moduleKey === BARISTA_AVAILABILITY_KEY) {
      res.json({ moduleKey, records: await baristaAvailabilityRows() });
      return;
    }

    const rows = await ModuleRecord.find({ moduleKey, active: true })
      .sort({ position: 1, updatedAt: -1 })
      .lean();

    res.json({
      moduleKey,
      records: rows.map((row) => ({
        recordId: row.recordId,
        data: row.data,
        position: row.position,
        updatedAt: row.updatedAt,
      })),
    });
  }));

  const upsertSchema = z.object({
    records: z.array(
      z.object({
        id: z.string().trim().min(1),
        data: z.unknown().optional(),
      }).passthrough(),
    ),
    removedIds: z.array(z.string().trim().min(1)).optional(),
  });

  router.put("/:key", requireAuth, asyncHandler(async (req: AuthedRequest, res) => {
    const moduleKey = String(req.params.key || "").trim();
    if (!moduleKey) {
      res.status(400).json({ error: "Module key is required" });
      return;
    }

    const parsed = upsertSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid module records payload" });
      return;
    }

    if (moduleKey === BARISTA_AVAILABILITY_KEY) {
      // Clock-in/out go through /api/barista; ignore client copies (they resurrected stale shifts).
      res.json({ ok: true, moduleKey, records: await baristaAvailabilityRows() });
      return;
    }

    const records = parsed.data.records;
    const removedIds = parsed.data.removedIds ?? [];

    const ops = records.map((record, position) => {
      const { id, ...rest } = record;
      const data = record.data && typeof record.data === "object" ? record.data : { id, ...rest };
      return {
        updateOne: {
          filter: { moduleKey, recordId: id },
          update: {
            $set: {
              moduleKey,
              recordId: id,
              data,
              position,
              active: true,
            },
          },
          upsert: true,
        },
      };
    });

    if (ops.length > 0) {
      await ModuleRecord.bulkWrite(ops, { ordered: false });
    }

    // Only remove ids the client explicitly asked to delete. Never deactivate
    // other users' records just because they were missing from this payload.
    if (removedIds.length > 0) {
      await ModuleRecord.updateMany(
        { moduleKey, recordId: { $in: removedIds } },
        { $set: { active: false } },
      );
    }

    const rows = await ModuleRecord.find({ moduleKey, active: true })
      .sort({ position: 1, updatedAt: -1 })
      .lean();

    io.emit("modules:updated", {
      moduleKey,
      at: new Date().toISOString(),
      actor: req.user?.name,
    });

    res.json({
      ok: true,
      moduleKey,
      records: rows.map((row) => ({
        recordId: row.recordId,
        data: row.data,
        position: row.position,
        updatedAt: row.updatedAt,
      })),
    });
  }));

  return router;
}
