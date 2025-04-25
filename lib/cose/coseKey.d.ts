/**
 * Exports the COSE Key as a raw key.
 *
 * It's effectively the same than:
 *
 * crypto.subtle.exportKey('raw', importedJWK)
 *
 * Note: This only works for KTY = EC.
 *
 * @param {Map<number, Uint8Array | number>} key - The COSE Key
 * @returns {Uint8Array} - The raw key
 */
declare const COSEKeyToRAW: (key: Map<number, Uint8Array | number> | Uint8Array) => Uint8Array;
export default COSEKeyToRAW;
