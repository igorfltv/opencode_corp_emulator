import { createHash, randomBytes } from "node:crypto";

export const random = () => randomBytes(32).toString("base64url");
export const digest = (text) => createHash("sha256").update(text).digest("hex");
export const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[character]);
