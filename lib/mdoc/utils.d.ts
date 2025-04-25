export declare const hmacSHA256: (key: ArrayBuffer, data: ArrayBuffer) => Promise<ArrayBuffer>;
/**
 * Calculates the ephemeral mac key for the device authentication.
 *
 * There are two cases for this function:
 * 1. SDeviceKey.Priv and EReaderKey.Pub for the mdoc
 * 2. EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader
 *
 * @param {Uint8Array} privateKey - The private key of the current party (COSE)
 * @param {Uint8Array} publicKey - The public key of the other party, (COSE)
 * @param {Uint8Array} sessionTranscriptBytes - The session transcript bytes
 * @returns {Uint8Array} - The ephemeral mac key
 */
export declare const calculateEphemeralMacKey: (privateKey: Uint8Array | Map<number, Uint8Array | number>, publicKey: Uint8Array | Map<number, Uint8Array | number>, sessionTranscriptBytes: Uint8Array) => Promise<Uint8Array>;
export declare const calculateDeviceAutenticationBytes: (sessionTranscript: Uint8Array | any, docType: string, nameSpaces: Record<string, Record<string, any>>) => Uint8Array;
export declare function getRandomBytes(len: number): Uint8Array;
export declare function fromPEM(pem: string): Uint8Array;
