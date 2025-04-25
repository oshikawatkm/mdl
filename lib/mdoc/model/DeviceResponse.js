"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DeviceResponse = void 0;
const cose_kit_1 = require("cose-kit");
const buffer_1 = require("buffer");
const MDoc_1 = require("./MDoc");
const DeviceSignedDocument_1 = require("./DeviceSignedDocument");
const parser_1 = require("../parser");
const utils_1 = require("../utils");
const cbor_1 = require("../../cbor");
/**
 * A builder class for creating a device response.
 */
class DeviceResponse {
    /**
     * Create a DeviceResponse builder.
     *
     * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
     *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
     * @returns {DeviceResponse} - A DeviceResponse builder.
     */
    static from(mdoc) {
        if (mdoc instanceof Uint8Array) {
            return new DeviceResponse((0, parser_1.parse)(mdoc));
        }
        return new DeviceResponse(mdoc);
    }
    constructor(mdoc) {
        this.useMac = true;
        this.nameSpaces = {};
        this.mdoc = mdoc;
    }
    /**
     *
     * @param pd - The presentation definition to use for the device response.
     * @returns {DeviceResponse}
     */
    usingPresentationDefinition(pd) {
        if (!pd.input_descriptors.length) {
            throw new Error('The Presentation Definition must have at least one Input Descriptor object.');
        }
        const hasDuplicates = pd.input_descriptors.some((id1, idx) => pd.input_descriptors.findIndex((id2) => id2.id === id1.id) !== idx);
        if (hasDuplicates) {
            throw new Error('Each Input Descriptor object must have a unique id property.');
        }
        this.pd = pd;
        return this;
    }
    /**
     * Set the session transcript data to use for the device response with the given handover data.
     * this is a shortcut to calling {@link usingSessionTranscriptBytes}(`<cbor encoding of [null, null, handover] in a Tagged 24 structure>`),
     * which is what the OID4VP protocol expects.
     *
     * @deprecated Use {@link usingSessionTranscriptForOID4VP} instead.
     * @param {string[]} handover - The handover data to use in the session transcript.
     * @returns {DeviceResponse}
     */
    usingHandover(handover) {
        this.usingSessionTranscriptBytes((0, cbor_1.cborEncode)(cbor_1.DataItem.fromData([
            null,
            null,
            handover
        ])));
        return this;
    }
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
    usingSessionTranscriptBytes(sessionTranscriptBytes) {
        if (this.sessionTranscriptBytes) {
            throw new Error('A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes');
        }
        this.sessionTranscriptBytes = sessionTranscriptBytes;
        return this;
    }
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
    usingSessionTranscriptForOID4VP(mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce) {
        this.usingSessionTranscriptBytes((0, cbor_1.cborEncode)(cbor_1.DataItem.fromData([
            null,
            null,
            [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce],
        ])));
        return this;
    }
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
    usingSessionTranscriptForWebAPI(deviceEngagementBytes, readerEngagementBytes, eReaderKeyBytes) {
        this.usingSessionTranscriptBytes((0, cbor_1.cborEncode)(cbor_1.DataItem.fromData([
            new cbor_1.DataItem({ buffer: deviceEngagementBytes }),
            new cbor_1.DataItem({ buffer: eReaderKeyBytes }),
            readerEngagementBytes,
        ])));
        return this;
    }
    /**
     * Add a name space to the device response.
     *
     * @param {string} nameSpace - The name space to add to the device response.
     * @param {Record<string, any>} data - The data to add to the name space.
     * @returns {DeviceResponse}
     */
    addDeviceNameSpace(nameSpace, data) {
        this.nameSpaces[nameSpace] = data;
        return this;
    }
    /**
     * Set the device's private key to be used for signing the device response.
     *
     * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
     * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
     * @returns {DeviceResponse}
     */
    authenticateWithSignature(devicePrivateKey, alg) {
        if (devicePrivateKey instanceof Uint8Array) {
            this.devicePrivateKey = devicePrivateKey;
        }
        else {
            this.devicePrivateKey = (0, cose_kit_1.COSEKeyFromJWK)(devicePrivateKey);
        }
        this.alg = alg;
        this.useMac = false;
        return this;
    }
    /**
     * Set the reader shared key to be used for signing the device response with MAC.
     *
     * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
     * @param  {Uint8Array} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
     * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
     * @returns {DeviceResponse}
     */
    authenticateWithMAC(devicePrivateKey, ephemeralPublicKey, alg) {
        if (devicePrivateKey instanceof Uint8Array) {
            this.devicePrivateKey = devicePrivateKey;
        }
        else {
            this.devicePrivateKey = (0, cose_kit_1.COSEKeyFromJWK)(devicePrivateKey);
        }
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.macAlg = alg;
        this.useMac = true;
        return this;
    }
    /**
     * Sign the device response and return the MDoc.
     *
     * @returns {Promise<MDoc>} - The device response as an MDoc.
     */
    async sign() {
        if (!this.pd)
            throw new Error('Must provide a presentation definition with .usingPresentationDefinition()');
        if (!this.sessionTranscriptBytes)
            throw new Error('Must provide the session transcript with either .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes');
        const docs = await Promise.all(this.pd.input_descriptors.map((id) => this.handleInputDescriptor(id)));
        return new MDoc_1.MDoc(docs);
    }
    async handleInputDescriptor(id) {
        const document = (this.mdoc.documents || []).find((d) => d.docType === id.id);
        if (!document) {
            // TODO; probl need to create a DocumentError here, but let's just throw for now
            throw new Error(`The mdoc does not have a document with DocType "${id.id}"`);
        }
        const nameSpaces = await this.prepareNamespaces(id, document);
        return new DeviceSignedDocument_1.DeviceSignedDocument(document.docType, {
            nameSpaces,
            issuerAuth: document.issuerSigned.issuerAuth,
        }, await this.getDeviceSigned(document.docType));
    }
    async getDeviceSigned(docType) {
        const deviceAuthenticationBytes = (0, utils_1.calculateDeviceAutenticationBytes)(this.sessionTranscriptBytes, docType, this.nameSpaces);
        const deviceSigned = {
            nameSpaces: this.nameSpaces,
            deviceAuth: this.useMac
                ? await this.getDeviceAuthMac(deviceAuthenticationBytes, this.sessionTranscriptBytes)
                : await this.getDeviceAuthSign(deviceAuthenticationBytes),
        };
        return deviceSigned;
    }
    async getDeviceAuthMac(deviceAuthenticationBytes, sessionTranscriptBytes) {
        const { kid } = (0, cose_kit_1.COSEKeyToJWK)(this.devicePrivateKey);
        const ephemeralMacKey = await (0, utils_1.calculateEphemeralMacKey)(this.devicePrivateKey, this.ephemeralPublicKey, sessionTranscriptBytes);
        const mac = await cose_kit_1.Mac0.create({ alg: this.macAlg }, { kid }, deviceAuthenticationBytes, ephemeralMacKey);
        return { deviceMac: mac };
    }
    async getDeviceAuthSign(cborData) {
        if (!this.devicePrivateKey)
            throw new Error('Missing devicePrivateKey');
        const key = await (0, cose_kit_1.importCOSEKey)(this.devicePrivateKey);
        const { kid } = (0, cose_kit_1.COSEKeyToJWK)(this.devicePrivateKey);
        const deviceSignature = await cose_kit_1.Sign1.sign({ alg: this.alg }, { kid }, buffer_1.Buffer.from(cborData), key);
        return { deviceSignature };
    }
    async prepareNamespaces(id, document) {
        const requestedFields = id.constraints.fields;
        const nameSpaces = {};
        for await (const field of requestedFields) {
            const result = await this.prepareDigest(field.path, document);
            if (!result) {
                // TODO: Do we add an entry to DocumentErrors if not found?
                console.log(`No matching field found for ${field.path}`);
                continue;
            }
            const { nameSpace, digest } = result;
            if (!nameSpaces[nameSpace])
                nameSpaces[nameSpace] = [];
            nameSpaces[nameSpace].push(digest);
        }
        return nameSpaces;
    }
    async prepareDigest(paths, document) {
        /**
         * path looks like this: "$['org.iso.18013.5.1']['family_name']"
         * the regex creates two groups with contents between "['" and "']"
         * the second entry in each group contains the result without the "'[" or "']"
         */
        for (const path of paths) {
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            const [[_1, nameSpace], [_2, elementIdentifier]] = [...path.matchAll(/\['(.*?)'\]/g)];
            if (!nameSpace)
                throw new Error(`Failed to parse namespace from path "${path}"`);
            if (!elementIdentifier)
                throw new Error(`Failed to parse elementIdentifier from path "${path}"`);
            const nsAttrs = document.issuerSigned.nameSpaces[nameSpace] || [];
            const digest = nsAttrs.find((d) => d.elementIdentifier === elementIdentifier);
            if (elementIdentifier.startsWith('age_over_')) {
                return this.handleAgeOverNN(elementIdentifier, nameSpace, nsAttrs);
            }
            if (digest) {
                return {
                    nameSpace,
                    digest,
                };
            }
        }
        return null;
    }
    handleAgeOverNN(request, nameSpace, attributes) {
        const ageOverList = attributes
            .map((a, i) => {
            const { elementIdentifier: key, elementValue: value } = a;
            return { key, value, index: i };
        })
            .filter((i) => i.key.startsWith('age_over_'))
            .map((i) => ({
            nn: parseInt(i.key.replace('age_over_', ''), 10),
            ...i,
        }))
            .sort((a, b) => a.nn - b.nn);
        const reqNN = parseInt(request.replace('age_over_', ''), 10);
        let item;
        // Find nearest TRUE
        item = ageOverList.filter((i) => i.value === true && i.nn >= reqNN)?.[0];
        if (!item) {
            // Find the nearest False
            item = ageOverList.sort((a, b) => b.nn - a.nn).filter((i) => i.value === false && i.nn <= reqNN)?.[0];
        }
        if (!item) {
            return null;
        }
        return {
            nameSpace,
            digest: attributes[item.index],
        };
    }
}
exports.DeviceResponse = DeviceResponse;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRGV2aWNlUmVzcG9uc2UuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWRvYy9tb2RlbC9EZXZpY2VSZXNwb25zZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFDQSx1Q0FBb0Y7QUFDcEYsbUNBQWdDO0FBRWhDLGlDQUE4QjtBQUc5QixpRUFBOEQ7QUFFOUQsc0NBQWtDO0FBQ2xDLG9DQUF1RjtBQUN2RixxQ0FBa0Q7QUFHbEQ7O0dBRUc7QUFDSCxNQUFhLGNBQWM7SUFZekI7Ozs7OztPQU1HO0lBQ0ksTUFBTSxDQUFDLElBQUksQ0FBQyxJQUF1QjtRQUN4QyxJQUFJLElBQUksWUFBWSxVQUFVLEVBQUU7WUFDOUIsT0FBTyxJQUFJLGNBQWMsQ0FBQyxJQUFBLGNBQUssRUFBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO1NBQ3hDO1FBQ0QsT0FBTyxJQUFJLGNBQWMsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUNsQyxDQUFDO0lBRUQsWUFBWSxJQUFVO1FBdEJkLFdBQU0sR0FBRyxJQUFJLENBQUM7UUFHZixlQUFVLEdBQXdDLEVBQUUsQ0FBQztRQW9CMUQsSUFBSSxDQUFDLElBQUksR0FBRyxJQUFJLENBQUM7SUFDbkIsQ0FBQztJQUVEOzs7O09BSUc7SUFDSSwyQkFBMkIsQ0FBQyxFQUEwQjtRQUMzRCxJQUFJLENBQUMsRUFBRSxDQUFDLGlCQUFpQixDQUFDLE1BQU0sRUFBRTtZQUNoQyxNQUFNLElBQUksS0FBSyxDQUFDLDZFQUE2RSxDQUFDLENBQUM7U0FDaEc7UUFFRCxNQUFNLGFBQWEsR0FBRyxFQUFFLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLENBQUMsRUFBRSxDQUFDLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsR0FBRyxDQUFDLEVBQUUsS0FBSyxHQUFHLENBQUMsRUFBRSxDQUFDLEtBQUssR0FBRyxDQUFDLENB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