/// <reference types="node" />
import { Options } from 'cbor-x';
declare const customInspectSymbol: unique symbol;
export declare class DateOnly extends Date {
    constructor(strDate?: string);
    get [Symbol.toStringTag](): string;
    toISOString(): string;
    toString(): string;
    toJSON(key?: any): string;
    [customInspectSymbol](): string;
}
export declare const cborDecode: (input: Buffer | Uint8Array, options?: Options) => any;
export declare const cborEncode: (obj: unknown, options?: Options) => Buffer;
export { DataItem } from './DataItem';
