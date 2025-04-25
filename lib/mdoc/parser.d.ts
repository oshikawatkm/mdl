/// <reference types="node" />
import { MDoc } from './model/MDoc';
/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export declare const parse: (encoded: Buffer | Uint8Array) => MDoc;
