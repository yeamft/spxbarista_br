import { Router } from "express";
import { z } from "zod";
import type { Server as SocketServer } from "socket.io";
import mongoose from "mongoose";
import { BaristaShift, toBaristaShiftDto } from "../models/BaristaShift.js";
import { User } from "../models/User.js";
import { BaristaCall, toBaristaCallDto } from "../models/BaristaCall.js";
import { requireAuth, requireRoles, type AuthedRequest } from "../middleware/auth.js";
import { asyncHandler } from "../lib/async-handler.js";
import { sendWebPush } from "../lib/web-push.js";

/** Only active Barista accounts count — admins/managers are never "on duty". */
export async function listShifts() {
  const docs = await BaristaShift.find().sort({ updatedAtIso: -1 }).lean();
  const ids = docs
    .map((doc) => doc.baristaId)
    .filter((id) => mongoose.isValidObjectId(id));
  const baristas = await User.find({ _id: { $in: ids }, role: "Barista", active: true })
    .select("_id")
    .lean();
  const baristaIds = new Set(baristas.map((user) => String(user._id)));
  return docs
    .filter((doc) => baristaIds.has(doc.baristaId))
    .map((doc) =>
    toBaristaShiftDto({
      ...doc,
      _id: doc._id,
    } as Parameters<typeof toBaristaShiftDto>[0]),
  );
}

async function onDuty() {
  const shifts = await listShifts();
  return shifts.filter((shift) => shift.status === "clocked_in");
}

async function listActiveCalls() {
  const docs = await BaristaCall.find({
    status: { $in: ["open", "acknowledged"] },
  })
    .sort({ createdAtIso: -1 })
    .limit(100)
    .lean();
  return docs.map((doc) =>
    toBaristaCallDto({
      ...doc,
      _id: doc._id,
    } as Parameters<typeof toBaristaCallDto>[0]),
  );
}

export function createBaristaRouter(io: SocketServer) {
  const router = Router();

  router.get("/availability", asyncHandler(async (_req, res) => {
    const available = await onDuty();
    const shifts = await listShifts();
    res.json({
      available,
      shifts,
      anyOnDuty: available.length > 0,
    });
  }));

  router.post("/clock-in", requireAuth, requireRoles("Barista"), asyncHandler(async (req: AuthedRequest, res) => {
    const baristaId = String(req.user!._id);
    const stamp = new Date().toISOString();
    const doc = await BaristaShift.findOneAndUpdate(
      { baristaId },
      {
        baristaId,
        baristaName: req.user!.name,
        status: "clocked_in",
        clockedInAt: stamp,
        clockedOutAt: undefined,
        updatedAtIso: stamp,
      },
      { upsert: true, new: true },
    );
    const shift = toBaristaShiftDto(doc);
    const available = await onDuty();
    io.emit("barista:availability", {
      type: "clock_in",
      shift,
      available,
      anyOnDuty: true,
    });
    res.json({ shift, available, anyOnDuty: true });
  }));

  router.post("/clock-out", requireAuth, asyncHandler(async (req: AuthedRequest, res) => {
    const parsed = z
      .object({
        baristaId: z.string().trim().min(1).optional(),
      })
      .safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid clock-out payload" });
      return;
    }
    const selfId = String(req.user!._id);
    const baristaId = parsed.data.baristaId || selfId;
    const canClockOutOthers = ["Administrator", "Manager", "Branch Manager", "Supervisor"].includes(
      req.user!.role,
    );
    if (baristaId !== selfId && !canClockOutOthers) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    const existing = await BaristaShift.findOne({ baristaId });
    const stamp = new Date().toISOString();
    const doc = await BaristaShift.findOneAndUpdate(
      { baristaId },
      {
        baristaId,
        baristaName: existing?.baristaName || "Barista",
        status: "clocked_out",
        clockedInAt: existing?.clockedInAt,
        clockedOutAt: stamp,
        updatedAtIso: stamp,
      },
      { upsert: true, new: true },
    );
    const shift = toBaristaShiftDto(doc);
    const available = await onDuty();
    io.emit("barista:availability", {
      type: "clock_out",
      shift,
      available,
      anyOnDuty: available.length > 0,
    });
    res.json({ shift, available, anyOnDuty: available.length > 0 });
  }));

  router.get("/calls", asyncHandler(async (_req, res) => {
    const calls = await listActiveCalls();
    res.json({ calls });
  }));

  router.post("/calls", requireAuth, asyncHandler(async (req: AuthedRequest, res) => {
    const parsed = z
      .object({
        id: z.string().trim().optional(),
        requestedBy: z.string().trim().min(1).optional(),
        requestedByRole: z.string().optional(),
        baristaName: z.string().optional(),
        location: z.string().optional(),
        note: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid call payload" });
      return;
    }

    const stamp = new Date().toISOString();
    const callId =
      parsed.data.id?.trim() ||
      `call-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

    const doc = await BaristaCall.create({
      callId,
      requestedBy: parsed.data.requestedBy?.trim() || req.user?.name || "Guest",
      requestedByRole: parsed.data.requestedByRole || req.user?.role || "",
      baristaName: parsed.data.baristaName?.trim() || "",
      location: parsed.data.location?.trim() || "Cafe",
      note: parsed.data.note?.trim() || "",
      status: "open",
      createdAtIso: stamp,
    });

    const call = toBaristaCallDto(doc);
    io.emit("barista:call", { type: "created", call, at: stamp });
    void sendWebPush(
      {
        title: "Incoming call",
        body: `${call.requestedBy} · ${call.location}`,
        url: "/app",
        tag: "barista-incoming-call",
        kind: "call",
        callId: call.id,
      },
      call.baristaName ? { names: [call.baristaName] } : { roles: ["Barista"] },
    );
    res.status(201).json({ call });
  }));

  router.patch("/calls/:id", asyncHandler(async (req, res) => {
    const parsed = z
      .object({
        status: z.enum(["open", "acknowledged", "done"]),
        acknowledgedBy: z.string().optional(),
      })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid call update" });
      return;
    }

    const existing = await BaristaCall.findOne({ callId: req.params.id });
    if (!existing) {
      res.status(404).json({ error: "Call not found" });
      return;
    }

    const stamp = new Date().toISOString();
    if (parsed.data.status === "acknowledged") {
      existing.status = "acknowledged";
      existing.acknowledgedAt = stamp;
      existing.acknowledgedBy =
        parsed.data.acknowledgedBy?.trim() || "Barista";
    } else if (parsed.data.status === "done") {
      existing.status = "done";
    } else {
      existing.status = "open";
      existing.acknowledgedAt = undefined;
      existing.acknowledgedBy = undefined;
    }
    await existing.save();

    const call = toBaristaCallDto(existing);
    io.emit("barista:call", {
      type: parsed.data.status === "acknowledged" ? "acknowledged" : "updated",
      call,
      at: stamp,
    });
    if (parsed.data.status === "acknowledged") {
      void sendWebPush(
        {
          title: "Barista is on the way",
          body: `${call.acknowledgedBy || "Barista"} accepted your call`,
          url: "/app",
          tag: `call-accepted-${call.id}`,
        },
        { names: [call.requestedBy], excludeNames: [call.acknowledgedBy || ""] },
      );
    }
    res.json({ call });
  }));

  return router;
}
