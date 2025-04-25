"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _Document_issuerNameSpaces, _Document_deviceKeyInfo, _Document_validityInfo, _Document_digestAlgorithm;
Object.defineProperty(exports, "__esModule", { value: true });
exports.Document = void 0;
const jose = __importStar(require("jose"));
const cose_kit_1 = require("cose-kit");
const utils_1 = require("../utils");
const cbor_1 = require("../../cbor");
const IssuerSignedItem_1 = require("../IssuerSignedItem");
const IssuerAuth_1 = __importDefault(require("./IssuerAuth"));
const IssuerSignedDocument_1 = require("./IssuerSignedDocument");
const DEFAULT_NS = 'org.iso.18013.5.1';
const addYears = (date, years) => {
    const r = new Date(date.getTime());
    r.setFullYear(date.getFullYear() + years);
    return r;
};
/**
 * Use this class when building new documents.
 *
 * This class allow you to build a document and sign it with the issuer's private key.
 */
class Document {
    constructor(doc = 'org.iso.18013.5.1.mDL') {
        _Document_issuerNameSpaces.set(this, {});
        _Document_deviceKeyInfo.set(this, void 0);
        _Document_validityInfo.set(this, {
            signed: new Date(),
            validFrom: new Date(),
            validUntil: addYears(new Date(), 1),
        });
        _Document_digestAlgorithm.set(this, 'SHA-256');
        this.docType = doc;
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    validateValues(values) {
        // TODO
        // validate required fields, no extra fields, data types, etc...
    }
    /**
     * Add a namespace to an unsigned document.
     *
     * @param {string} namespace - The namespace to add.
     * @param {Record<string, any>} values - The values to add to the namespace.
     * @returns {Document} - The document
     */
    addIssuerNameSpace(namespace, values) {
        if (namespace === DEFAULT_NS) {
            this.validateValues(values);
        }
        __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")[namespace] = __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")[namespace] ?? [];
        const addAttribute = (key, value) => {
            let elementValue = value;
            if (namespace === DEFAULT_NS) {
                // the following namespace attributes must be a full-date as specified in RFC 3339
                if (['birth_date', 'issue_date', 'expiry_date'].includes(key) && typeof value === 'string') {
                    elementValue = new cbor_1.DateOnly(value);
                }
                if (key === 'driving_privileges' && Array.isArray(value)) {
                    value.forEach((v, i) => {
                        if (typeof v.issue_date === 'string') {
                            elementValue[i].issue_date = new cbor_1.DateOnly(v.issue_date);
                        }
                        if (typeof v.expiry_date === 'string') {
                            elementValue[i].expiry_date = new cbor_1.DateOnly(v.expiry_date);
                        }
                    });
                }
            }
            const digestID = __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")[namespace].length;
            const issuerSignedItem = IssuerSignedItem_1.IssuerSignedItem.create(digestID, key, elementValue);
            __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")[namespace].push(issuerSignedItem);
        };
        for (const [key, value] of Object.entries(values)) {
            addAttribute(key, value);
        }
        return this;
    }
    /**
     * Get the values in a namespace.
     *
     * @param {string} namespace - The namespace to add.
     * @returns {Record<string, any>} - The values in the namespace as an object
     */
    getIssuerNameSpace(namespace) {
        const nameSpace = __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")[namespace];
        return Object.fromEntries(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]));
    }
    /**
     * Add the device public key which will be include in the issuer signature.
     * The device public key could be in JWK format or as COSE_Key format.
     *
     * @param params
     * @param {jose.JWK | Uint8Array} params.devicePublicKey - The device public key.
     */
    addDeviceKeyInfo({ deviceKey }) {
        const deviceKeyCOSEKey = deviceKey instanceof Uint8Array ?
            deviceKey :
            (0, cose_kit_1.COSEKeyFromJWK)(deviceKey);
        const decodedCoseKey = (0, cbor_1.cborDecode)(deviceKeyCOSEKey);
        __classPrivateFieldSet(this, _Document_deviceKeyInfo, {
            deviceKey: decodedCoseKey,
        }, "f");
        return this;
    }
    /**
     * Add validity info to the document that will be used in the issuer signature.
     *
     * @param info - the validity info
     * @param {Date} [info.signed] - The date the document is signed. default: now
     * @param {Date} [info.validFrom] - The date the document is valid from. default: signed
     * @param {Date} [info.validUntil] - The date the document is valid until. default: signed + 1 year
     * @param {Date} [info.expectedUpdate] - [Optional] The date the document is expected to be re-signed and potentially have its data updated.
     * @returns
     */
    addValidityInfo(info = {}) {
        const signed = info.signed ?? new Date();
        const validFrom = info.validFrom ?? signed;
        const validUntil = info.validUntil ?? addYears(signed, 1);
        __classPrivateFieldSet(this, _Document_validityInfo, {
            signed,
            validFrom,
            validUntil,
        }, "f");
        if (info.expectedUpdate) {
            __classPrivateFieldGet(this, _Document_validityInfo, "f").expectedUpdate = info.expectedUpdate;
        }
        return this;
    }
    /**
     * Set the digest algorithm used for the value digests in the issuer signature.
     *
     * The default is SHA-256.
     *
     * @param {DigestAlgorithm} digestAlgorithm - The digest algorithm to use.
     * @returns
     */
    useDigestAlgorithm(digestAlgorithm) {
        __classPrivateFieldSet(this, _Document_digestAlgorithm, digestAlgorithm, "f");
        return this;
    }
    /**
     * Generate the issuer signature for the document.
     *
     * @param {Object} params - The parameters object
     * @param {jose.JWK | Uint8Array} params.issuerPrivateKey - The issuer's private key either in JWK format or COSE_KEY format as buffer.
     * @param {string | Uint8Array} params.issuerCertificate - The issuer's certificate in pem format or as a buffer.
     * @param {SupportedAlgs} params.alg - The algorhitm used for the MSO signature.
     * @param {string | Uint8Array} [params.kid] - The key id of the issuer's private key. default: issuerPrivateKey.kid
     * @returns {Promise<IssuerSignedDoc>} - The signed document
     */
    async sign(params) {
        if (!__classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")) {
            throw new Error('No namespaces added');
        }
        const issuerPublicKeyBuffer = typeof params.issuerCertificate === 'string' ?
            (0, utils_1.fromPEM)(params.issuerCertificate) :
            params.issuerCertificate;
        const issuerPrivateKeyJWK = params.issuerPrivateKey instanceof Uint8Array ?
            (0, cose_kit_1.COSEKeyToJWK)(params.issuerPrivateKey) :
            params.issuerPrivateKey;
        const issuerPrivateKey = await jose.importJWK(issuerPrivateKeyJWK);
        const valueDigests = new Map(await Promise.all(Object.entries(__classPrivateFieldGet(this, _Document_issuerNameSpaces, "f")).map(async ([namespace, items]) => {
            const digestMap = new Map();
            await Promise.all(items.map(async (item, index) => {
                const hash = await item.calculateDigest(__classPrivateFieldGet(this, _Document_digestAlgorithm, "f"));
                digestMap.set(index, new Uint8Array(hash));
            }));
            return [namespace, digestMap];
        })));
        const mso = {
            version: '1.0',
            digestAlgorithm: __classPrivateFieldGet(this, _Document_digestAlgorithm, "f"),
            valueDigests,
            deviceKeyInfo: __classPrivateFieldGet(this, _Document_deviceKeyInfo, "f"),
            docType: this.docType,
            validityInfo: __classPrivateFieldGet(this, _Document_validityInfo, "f"),
        };
        const payload = (0, cbor_1.cborEncode)(cbor_1.DataItem.fromData(mso));
        const protectedHeader = { alg: params.alg };
        const unprotectedHeader = {
            kid: params.kid ?? issuerPrivateKeyJWK.kid,
            x5chain: [issuerPublicKeyBuffer],
        };
        const issuerAuth = await IssuerAuth_1.default.sign(protectedHeader, unprotectedHeader, payload, issuerPrivateKey);
        const issuerSigned = {
            issuerAuth,
            nameSpaces: __classPrivateFieldGet(this, _Document_issuerNameSpaces, "f"),
        };
        return new IssuerSignedDocument_1.IssuerSignedDocument(this.docType, issuerSigned);
    }
}
exports.Document = Document;
_Document_issuerNameSpaces = new WeakMap(), _Document_deviceKeyInfo = new WeakMap(), _Document_validityInfo = new WeakMap(), _Document_digestAlgorithm = new WeakMap();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiRG9jdW1lbnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWRvYy9tb2RlbC9Eb2N1bWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLDJDQUE2QjtBQUM3Qix1Q0FBOEY7QUFDOUYsb0NBQW1DO0FBQ25DLHFDQUF3RTtBQUN4RSwwREFBdUQ7QUFDdkQsOERBQXNDO0FBRXRDLGlFQUE4RDtBQUU5RCxNQUFNLFVBQVUsR0FBRyxtQkFBbUIsQ0FBQztBQUV2QyxNQUFNLFFBQVEsR0FBRyxDQUFDLElBQVUsRUFBRSxLQUFhLEVBQVEsRUFBRTtJQUNuRCxNQUFNLENBQUMsR0FBRyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsQ0FBQztJQUNuQyxDQUFDLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxXQUFXLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztJQUMxQyxPQUFPLENBQUMsQ0FBQztBQUNYLENBQUMsQ0FBQztBQUVGOzs7O0dBSUc7QUFDSCxNQUFhLFFBQVE7SUFXbkIsWUFBWSxNQUFlLHVCQUF1QjtRQVRsRCxxQ0FBc0MsRUFBRSxFQUFDO1FBQ3pDLDBDQUE4QjtRQUM5QixpQ0FBOEI7WUFDNUIsTUFBTSxFQUFFLElBQUksSUFBSSxFQUFFO1lBQ2xCLFNBQVMsRUFBRSxJQUFJLElBQUksRUFBRTtZQUNyQixVQUFVLEVBQUUsUUFBUSxDQUFDLElBQUksSUFBSSxFQUFFLEVBQUUsQ0FBQyxDQUFDO1NBQ3BDLEVBQUM7UUFDRixvQ0FBb0MsU0FBUyxFQUFDO1FBRzVDLElBQUksQ0FBQyxPQUFPLEdBQUcsR0FBRyxDQUFDO0lBQ3JCLENBQUM7SUFFRCw2REFBNkQ7SUFDckQsY0FBYyxDQUFDLE1BQTJCO1FBQ2hELE9BQU87UUFDUCxnRUFBZ0U7SUFDbEUsQ0FBQztJQUVEOzs7Ozs7T0FNRztJQUNILGtCQUFrQixD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