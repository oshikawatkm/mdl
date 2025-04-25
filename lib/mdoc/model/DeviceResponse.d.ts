/// <reference types="node" />
import * as jose from 'jose';
import { Buffer } from 'buffer';
import { PresentationDefinition } from './PresentationDefinition';
import { MDoc } from './MDoc';
import { MacSupportedAlgs, SupportedAlgs } from './types';
/**
 * A builder class for creating a device response.
 */
export declare class DeviceResponse {
    private mdoc;
    private pd;
    private sessionTranscriptBytes;
    private useMac;
    private devicePrivateKey;
    deviceResponseCbor: Buffer;
    nameSpaces: Record<string, Record<string, any>>;
    private alg;
    private macAlg;
    private ephemeralPublicKey;
    /**
     * Create a DeviceResponse builder.
     *
     * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
     *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
     * @returns {DeviceResponse} - A DeviceResponse builder.
     */
    static from(mdoc: MDoc | Uint8Array): DeviceResponse;
    constructor(mdoc: MDoc);
    /**
     *
     * @param pd - The presentation definition to use for the device response.
     * @returns {DeviceResponse}
     */
    usingPresentationDefinition(pd: PresentationDefinition): DeviceResponse;
    /**
     * Set the session transcript data to use for the device response with the given handover data.
     * this is a shortcut to calling {@link usingSessionTranscriptBytes}(`<cbor encoding of [null, null, handover] in a Tagged 24 structure>`),
     * which is what the OID4VP protocol expects.
     *
     * @deprecated Use {@link usingSessionTranscriptForOID4VP} instead.
     * @param {string[]} handover - The handover data to use in the session transcript.
     * @returns {DeviceResponse}
     */
    usingHandover(handover: string[]): DeviceResponse;
    /**
     * Set the session transcript data to use for the device response.
     *
     * This is arbitrary and should match the session transcript as it will be calculated by the verifier.
     * The transcript must be a CBOR encoded DataItem of an array, there is no further requirement.
     *
     * Example: `usingSessionTranscriptBytes(cborEncode(DataItem.fromData([a,b,c])))` where `a`, `b` and `c` can be anything including `null`.
     *
     * It is preferable to use {@link usingSessionTranscriptForOID4VP} or {@link usingSessionTranscriptForWebAPI} when possible.
     *
     * @param {Buffer} sessionTranscriptBytes - The sessionTranscriptBytes data to use in the session transcript.
     * @returns {DeviceResponse}
     */
    usingSessionTranscriptBytes(sessionTranscriptBytes: Buffer): DeviceResponse;
    /**
     * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex B (OID4VP), 2023 draft.
     *
     * This should match the session transcript as it will be calculated by the verifier.
     *
     * @param {string} mdocGeneratedNonce - A cryptographically random number with sufficient entropy.
     * @param {string} clientId - The client_id Authorization Request parameter from the Authorization Request Object.
     * @param {string} responseUri - The response_uri Authorization Request parameter from the Authorization Request Object.
     * @param {string} verifierGeneratedNonce - The nonce Authorization Request parameter from the Authorization Request Object.
     * @returns {DeviceResponse}
     */
    usingSessionTranscriptForOID4VP(mdocGeneratedNonce: string, clientId: string, responseUri: string, verifierGeneratedNonce: string): DeviceResponse;
    /**
     * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex A (Web API), 2023 draft.
     *
     * This should match the session transcript as it will be calculated by the verifier.
     *
     * @param {Buffer} deviceEngagementBytes - The device engagement, encoded as a Tagged 24 cbor
     * @param {Buffer} readerEngagementBytes - The reader engagement, encoded as a Tagged 24 cbor
     * @param {Buffer} eReaderKeyBytes - The reader ephemeral public key as a COSE Key, encoded as a Tagged 24 cbor
     * @returns {DeviceResponse}
     */
    usingSessionTranscriptForWebAPI(deviceEngagementBytes: Buffer, readerEngagementBytes: Buffer, eReaderKeyBytes: Buffer): DeviceResponse;
    /**
     * Add a name space to the device response.
     *
     * @param {string} nameSpace - The name space to add to the device response.
     * @param {Record<string, any>} data - The data to add to the name space.
     * @returns {DeviceResponse}
     */
    addDeviceNameSpace(nameSpace: string, data: Record<string, any>): DeviceResponse;
    /**
     * Set the device's private key to be used for signing the device response.
     *
     * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
     * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
     * @returns {DeviceResponse}
     */
    authenticateWithSignature(devicePrivateKey: jose.JWK | Uint8Array, alg: SupportedAlgs): DeviceResponse;
    /**
     * Set the reader shared key to be used for signing the device response with MAC.
     *
     * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
     * @param  {Uint8Array} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
     * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
     * @returns {DeviceResponse}
     */
    authenticateWithMAC(devicePrivateKey: jose.JWK | Uint8Array, ephemeralPublicKey: Uint8Array, alg: MacSupportedAlgs): DeviceResponse;
    /**
     * Sign the device response and return the MDoc.
     *
     * @returns {Promise<MDoc>} - The device response as an MDoc.
     */
    sign(): Promise<MDoc>;
    private handleInputDescriptor;
    private getDeviceSigned;
    private getDeviceAuthMac;
    private getDeviceAuthSign;
    private prepareNamespaces;
    private prepareDigest;
    private handleAgeOverNN;
}
