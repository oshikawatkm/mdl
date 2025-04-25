export declare const encoder: TextEncoder;
export declare const decoder: TextDecoder;
export declare function concat(...buffers: Uint8Array[]): Uint8Array;
export declare function areEqual(buf1: Uint8Array, buf2: Uint8Array): boolean;
export declare const fromUTF8: (input: string) => Uint8Array;
export declare const toUTF8: (input: Uint8Array) => string;
