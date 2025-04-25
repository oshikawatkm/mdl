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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromPEM = exports.getRandomBytes = exports.calculateDeviceAutenticationBytes = exports.calculateEphemeralMacKey = exports.hmacSHA256 = void 0;
const pkijs = __importStar(require("pkijs"));
const p256_1 = require("@noble/curves/p256");
const p384_1 = require("@noble/curves/p384");
const p521_1 = require("@noble/curves/p521");
const webcrypto = __importStar(require("uncrypto"));
const buffer_1 = require("buffer");
const hkdf_1 = __importDefault(require("@panva/hkdf"));
const cose_kit_1 = require("cose-kit");
const cbor_1 = require("../cbor");
const DataItem_1 = require("../cbor/DataItem");
const coseKey_1 = __importDefault(require("../cose/coseKey"));
const { subtle } = webcrypto;
pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: webcrypto, subtle }));
const hmacSHA256 = async (key, data) => {
    const saltHMACKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const hmac = await subtle.sign('HMAC', saltHMACKey, data);
    return hmac;
};
exports.hmacSHA256 = hmacSHA256;
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
const calculateEphemeralMacKey = async (privateKey, publicKey, sessionTranscriptBytes) => {
    const { kty, crv } = (0, cose_kit_1.COSEKeyToJWK)(privateKey);
    const privkey = (0, coseKey_1.default)(privateKey); // only d
    const pubkey = (0, coseKey_1.default)(publicKey); // 0x04 || x || y
    let ikm;
    if ((kty === 'EC')) {
        if (crv === 'P-256') {
            ikm = p256_1.p256
                .getSharedSecret(buffer_1.Buffer.from(privkey).toString('hex'), buffer_1.Buffer.from(pubkey).toString('hex'), true)
                .slice(1);
        }
        else if (crv === 'P-384') {
            ikm = p384_1.p384
                .getSharedSecret(buffer_1.Buffer.from(privkey).toString('hex'), buffer_1.Buffer.from(pubkey).toString('hex'), true)
                .slice(1);
        }
        else if (crv === 'P-521') {
            ikm = p521_1.p521
                .getSharedSecret(buffer_1.Buffer.from(privkey).toString('hex'), buffer_1.Buffer.from(pubkey).toString('hex'), true)
                .slice(1);
        }
        else {
            throw new Error(`unsupported EC curve: ${crv}`);
        }
    }
    else {
        throw new Error(`unsupported key type: ${kty}`);
    }
    const salt = new Uint8Array(await subtle.digest('SHA-256', sessionTranscriptBytes));
    const info = buffer_1.Buffer.from('EMacKey', 'utf-8');
    const result = await (0, hkdf_1.default)('sha256', ikm, salt, info, 32);
    return result;
};
exports.calculateEphemeralMacKey = calculateEphemeralMacKey;
const calculateDeviceAutenticationBytes = (sessionTranscript, docType, nameSpaces) => {
    let decodedSessionTranscript;
    if (sessionTranscript instanceof Uint8Array) {
        // assume is encoded in a DataItem
        decodedSessionTranscript = (0, cbor_1.cborDecode)(sessionTranscript).data;
    }
    else {
        decodedSessionTranscript = sessionTranscript;
    }
    const nameSpacesAsMap = new Map(Object.entries(nameSpaces).map(([ns, items]) => [ns, new Map(Object.entries(items))]));
    const encode = DataItem_1.DataItem.fromData([
        'DeviceAuthentication',
        decodedSessionTranscript,
        docType,
        DataItem_1.DataItem.fromData(nameSpacesAsMap),
    ]);
    const result = (0, cbor_1.cborEncode)(encode);
    return result;
};
exports.calculateDeviceAutenticationBytes = calculateDeviceAutenticationBytes;
function getRandomBytes(len) {
    return webcrypto.getRandomValues(new Uint8Array(len));
}
exports.getRandomBytes = getRandomBytes;
function fromPEM(pem) {
    const base64 = pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, '');
    return buffer_1.Buffer.from(base64, 'base64');
}
exports.fromPEM = fromPEM;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWRvYy91dGlscy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLDZDQUErQjtBQUMvQiw2Q0FBMEM7QUFDMUMsNkNBQTBDO0FBQzFDLDZDQUEwQztBQUMxQyxvREFBc0M7QUFDdEMsbUNBQWdDO0FBQ2hDLHVEQUErQjtBQUMvQix1Q0FBd0M7QUFFeEMsa0NBQWlEO0FBQ2pELCtDQUE0QztBQUM1Qyw4REFBMkM7QUFFM0MsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLFNBQVMsQ0FBQztBQUU3QixLQUFLLENBQUMsU0FBUyxDQUFDLFdBQVcsRUFBRSxJQUFJLEtBQUssQ0FBQyxZQUFZLENBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLE1BQU0sRUFBRSxTQUFTLEVBQUUsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFDO0FBRWhHLE1BQU0sVUFBVSxHQUFHLEtBQUssRUFDN0IsR0FBZ0IsRUFDaEIsSUFBaUIsRUFDSyxFQUFFO0lBQ3hCLE1BQU0sV0FBVyxHQUFHLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FDeEMsS0FBSyxFQUNMLEdBQUcsRUFDSCxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxFQUNqQyxLQUFLLEVBQ0wsQ0FBQyxNQUFNLEVBQUUsUUFBUSxDQUFDLENBQ25CLENBQUM7SUFFRixNQUFNLElBQUksR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLFdBQVcsRUFBRSxJQUFJLENBQUMsQ0FBQztJQUUxRCxPQUFPLElBQUksQ0FBQztBQUNkLENBQUMsQ0FBQztBQWZXLFFBQUEsVUFBVSxjQWVyQjtBQUVGOzs7Ozs7Ozs7OztHQVdHO0FBQ0ksTUFBTSx3QkFBd0IsR0FBRyxLQUFLLEVBQzNDLFVBQXlELEVBQ3pELFNBQXdELEVBQ3hELHNCQUFrQyxFQUNi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