import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import {
  hashPassword,
  isValidStaffPin,
  mapAppRoleToMongo,
  toPublicUser,
  User,
} from "../models/User.js";
import { requireAuth, signToken, type AuthedRequest } from "../middleware/auth.js";

export const authRouter = Router();

const loginSchema = z.object({
  login: z.string().trim().min(1),
  password: z.string().min(1),
});

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid login payload" });
    return;
  }

  const login = parsed.data.login.trim();
  const password = parsed.data.password.trim();
  const pin = isValidStaffPin(password) ? password : isValidStaffPin(login) ? login : "";

  let user = pin
    ? await User.findOne({
        active: true,
        $or: [{ pin }, { username: pin.toLowerCase() }],
      })
    : null;

  if (!user) {
    const key = login.toLowerCase();
    user = await User.findOne({
      active: true,
      $or: [{ email: key }, { username: key }],
    });
  }

  if (!user) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  let hashOk = false;
  try {
    hashOk = Boolean(user.passwordHash) && (await bcrypt.compare(password, user.passwordHash));
  } catch {
    hashOk = false;
  }
  const pinOk = Boolean(pin) && (user.pin === pin || user.username === pin);

  if (!hashOk && !pinOk) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  if (pin && (user.pin !== pin || user.username !== pin || !hashOk)) {
    user.pin = pin;
    user.username = pin;
    if (!hashOk) user.passwordHash = await hashPassword(pin);
    await user.save();
  }

  const token = signToken(user);
  res.json({
    token,
    user: toPublicUser(user),
  });
});

authRouter.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  res.json(toPublicUser(req.user!));
});

/** Public staff directory (no password hashes) for PIN uniqueness / name lists. */
authRouter.get("/directory", async (_req, res) => {
  const users = await User.find({ active: true })
    .select("name role branch avatar username pin")
    .sort({ name: 1 })
    .lean();
  res.json({
    users: users.map((user) =>
      toPublicUser({
        _id: user._id,
        email: null,
        username: user.username,
        pin: user.pin,
        name: user.name,
        role: user.role,
        branch: user.branch,
        avatar: user.avatar,
      }),
    ),
  });
});

function avatarFromName(name: string) {
  return name
    .split(/\s+/)
    .map((part) => part[0] ?? "")
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

function isAppUserRole(role: string) {
  return mapAppRoleToMongo(role) === "User";
}

const identifySchema = z.object({
  userId: z.string().trim().min(1).optional(),
  name: z.string().trim().min(1).optional(),
}).refine((value) => Boolean(value.userId || value.name), {
  message: "userId or name is required",
});

/**
 * Trust-based cafe identity for ordering Users (no PIN).
 * Barista / Manager / Admin must use POST /login with PIN.
 */
authRouter.post("/identify", async (req, res) => {
  const parsed = identifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || "Invalid identify payload" });
    return;
  }

  const { userId, name } = parsed.data;
  let user = null as Awaited<ReturnType<typeof User.findById>> | null;

  if (userId) {
    user = await User.findOne({ _id: userId, active: true });
  } else if (name) {
    const key = name.trim().toLowerCase();
    user = await User.findOne({
      active: true,
      name: new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i"),
    });
  }

  if (!user) {
    res.status(404).json({ error: "Person not found" });
    return;
  }

  if (!isAppUserRole(user.role)) {
    res.status(403).json({ error: "Staff must sign in with a PIN" });
    return;
  }

  const token = signToken(user);
  res.json({
    token,
    user: toPublicUser(user),
  });
});

const registerPinSchema = z.object({
  name: z.string().trim().min(1),
  pin: z.string().trim().regex(/^\d{2}$|^\d{4}$/, "PIN must be 2 or 4 digits"),
  role: z.string().default("User"),
  branch: z.string().default("Main Office"),
});

/** Self-serve coffee-office registration (2- or 4-digit PIN = login). Staff/PIN accounts. */
authRouter.post("/register-pin", async (req, res) => {
  const parsed = registerPinSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: parsed.error.issues[0]?.message || "Invalid register payload",
    });
    return;
  }

  const { name, pin, branch } = parsed.data;
  const role = mapAppRoleToMongo(parsed.data.role);

  const taken = await User.findOne({
    $or: [{ pin }, { username: pin }],
  });
  if (taken) {
    res.status(409).json({ error: "That PIN is already in use" });
    return;
  }

  try {
    const user = await User.create({
      name,
      username: pin,
      pin,
      role,
      branch: branch.trim() || "Main Office",
      passwordHash: await hashPassword(pin),
      avatar: avatarFromName(name),
      active: true,
    });

    const token = signToken(user);
    res.status(201).json({
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not create user";
    if (/duplicate|E11000/i.test(message)) {
      res.status(409).json({ error: "That PIN is already in use" });
      return;
    }
    res.status(409).json({ error: message });
  }
});

const registerNameSchema = z.object({
  name: z.string().trim().min(1),
  branch: z.string().default("Main Office"),
});

/** Self-serve ordering User — name only, no PIN. Issues a session. */
authRouter.post("/register-name", async (req, res) => {
  const parsed = registerNameSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || "Invalid register payload" });
    return;
  }

  const name = parsed.data.name.trim();
  const branch = parsed.data.branch.trim() || "Main Office";
  const key = name.toLowerCase();

  const existing = await User.findOne({
    active: true,
    name: new RegExp(`^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i"),
    role: { $in: ["User", "Cashier", "Coffee House Staff"] },
  });
  if (existing) {
    const token = signToken(existing);
    res.status(200).json({
      token,
      user: toPublicUser(existing),
    });
    return;
  }

  const username = `u-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
  try {
    const user = await User.create({
      name,
      username,
      pin: undefined,
      role: "User",
      branch,
      // Unusable random hash — name Users sign in via /identify, not PIN.
      passwordHash: await hashPassword(`name-only-${username}-${Math.random().toString(36)}`),
      avatar: avatarFromName(name),
      active: true,
    });
    const token = signToken(user);
    res.status(201).json({
      token,
      user: toPublicUser(user),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not create user";
    res.status(409).json({ error: message });
  }
});

const registerSchema = z.object({
  name: z.string().trim().min(1),
  email: z.string().email().optional(),
  username: z.string().trim().min(2).optional(),
  pin: z.string().trim().regex(/^\d{2}$|^\d{4}$/).optional(),
  password: z.string().min(2).optional(),
  role: z.string().default("User"),
  branch: z.string().default("Main Office"),
});

authRouter.post("/register", requireAuth, async (req: AuthedRequest, res) => {
  if (!["Administrator", "Manager", "Branch Manager"].includes(req.user?.role || "")) {
    res.status(403).json({ error: "Forbidden" });
    return;
  }

  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid register payload", details: parsed.error.flatten() });
    return;
  }

  const data = parsed.data;
  const role = mapAppRoleToMongo(data.role);
  const pin =
    data.pin ||
    (data.password && isValidStaffPin(data.password) ? data.password : undefined);

  // Ordering Users may be created without a PIN; staff roles still need one.
  if (role !== "User" && !pin && !data.password && !data.email && !data.username) {
    res.status(400).json({ error: "PIN or password is required for staff roles" });
    return;
  }

  const username =
    (data.username || pin || data.email || (role === "User" ? `u-${Date.now().toString(36)}` : ""))
      .toLowerCase();
  if (!username && !data.email) {
    res.status(400).json({ error: "Email, username, or PIN is required" });
    return;
  }

  if (pin) {
    const taken = await User.findOne({ $or: [{ pin }, { username: pin }] });
    if (taken) {
      res.status(409).json({ error: "That PIN is already in use" });
      return;
    }
  }

  try {
    const passwordSource =
      pin ||
      data.password ||
      (role === "User" ? `name-only-${username}-${Math.random().toString(36)}` : "");
    if (!passwordSource) {
      res.status(400).json({ error: "PIN or password is required" });
      return;
    }

    const user = await User.create({
      name: data.name,
      email: data.email?.toLowerCase(),
      username: username || undefined,
      pin: pin || undefined,
      role,
      branch: data.branch,
      passwordHash: await hashPassword(passwordSource),
      avatar: avatarFromName(data.name),
      active: true,
    });
    res.status(201).json(toPublicUser(user));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not create user";
    if (/duplicate|E11000/i.test(message)) {
      res.status(409).json({ error: "That PIN is already in use" });
      return;
    }
    res.status(409).json({ error: message });
  }
});
