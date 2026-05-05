// Mirror of the backend registry — used for dropdown options and PA#
// labelling on the client without a round-trip to the server.

export const PRIMITIVES = [
  { name: "OWF", full: "One-Way Function", pa: 1 },
  { name: "OWP", full: "One-Way Permutation", pa: 1 },
  { name: "PRG", full: "Pseudorandom Generator", pa: 1 },
  { name: "PRF", full: "Pseudorandom Function", pa: 2 },
  { name: "PRP", full: "Pseudorandom Permutation", pa: 4 },
  { name: "MAC", full: "Message Authentication Code", pa: 5 },
  { name: "CRHF", full: "Collision-Resistant Hash", pa: 8 },
  { name: "HMAC", full: "Hash-based MAC", pa: 10 },
];

export const FOUNDATIONS = [
  { name: "AES", full: "AES-128 (concrete PRP/PRF)" },
  { name: "DLP", full: "DLP — g^x mod p (concrete OWF/OWP)" },
];

export function findPrimitive(name) {
  return PRIMITIVES.find((p) => p.name === name) || null;
}
