// Minimal offline-build declarations for environments without @types/node.
// When @types/node is installed, its declarations provide the full API types.
declare module 'node:crypto' {
  export function createHash(algorithm: string): {
    update(data: string | Uint8Array): any;
    digest(encoding: 'hex'): string;
  };
}
declare module 'node:fs' {
  export function readFileSync(path: string): Uint8Array;
}
declare module 'node:assert' {
  export const strict: any;
}
