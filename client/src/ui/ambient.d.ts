// Types for the one runtime dependency that ships none.
//
// `@types/qrcode` is deliberately not installed (vendor/decimen/PROVENANCE.md): it is a
// types-only package with no pinning argument behind it, and only two of its declarations
// are used. Declaring them here keeps the dependency list at what actually executes.
//
// Everything else the UI touches is in lib.dom: WakeLock, WakeLockSentinel and
// requestVideoFrameCallback are all typed. `torch` and `focusMode` are not, and are
// handled where they belong, in vendor/decimen/platform.ts.

// The deep path, not the package entry. `qrcode`'s browser entry pulls in its SVG renderer,
// which builds a tag string containing the w3.org namespace URL, and that string then
// survives into dist/ and trips the no-external-origin build assertion. It is an XML
// namespace and would never be fetched, but "no http(s) origin anywhere in the bundle" is
// worth more as a rule with no exceptions than as a rule with one explained exception.
// The core module is the same create() the entry re-exports, minus three renderers we do
// not use. qrcode declares no "exports" map, so the deep path is a supported import.
declare module 'qrcode/lib/core/qrcode.js' {
  /** Byte mode with a Uint8Array is what carries a frame; the rest are unused. */
  export interface QrSegment {
    data: Uint8Array;
    mode: 'byte';
  }

  export interface QrCreateOptions {
    errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
    version?: number;
    maskPattern?: number;
  }

  export interface QrCode {
    version: number;
    /** Row-major module matrix; truthy means dark. `size` is modules per side. */
    modules: { size: number; data: Uint8Array };
  }

  export function create(data: string | QrSegment[], options?: QrCreateOptions): QrCode;
}
