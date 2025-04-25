"use strict";
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
var _IssuerAuth_decodedPayload, _IssuerAuth_certificate;
Object.defineProperty(exports, "__esModule", { value: true });
const cose_kit_1 = require("cose-kit");
const x509_1 = require("@peculiar/x509");
const cbor_1 = require("../../cbor");
const DataItem_1 = require("../../cbor/DataItem");
/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
class IssuerAuth extends cose_kit_1.Sign1 {
    constructor(protectedHeader, unprotectedHeader, payload, signature) {
        super(protectedHeader, unprotectedHeader, payload, signature);
        _IssuerAuth_decodedPayload.set(this, void 0);
        _IssuerAuth_certificate.set(this, void 0);
    }
    get decodedPayload() {
        if (__classPrivateFieldGet(this, _IssuerAuth_decodedPayload, "f")) {
            return __classPrivateFieldGet(this, _IssuerAuth_decodedPayload, "f");
        }
        let decoded = (0, cbor_1.cborDecode)(this.payload);
        decoded = decoded instanceof DataItem_1.DataItem ? decoded.data : decoded;
        decoded = Object.fromEntries(decoded);
        const mapValidityInfo = (validityInfo) => {
            if (!validityInfo) {
                return validityInfo;
            }
            return Object.fromEntries([...validityInfo.entries()].map(([key, value]) => {
                return [key, value instanceof Uint8Array ? (0, cbor_1.cborDecode)(value) : value];
            }));
        };
        const result = {
            ...decoded,
            validityInfo: mapValidityInfo(decoded.validityInfo),
            validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : decoded.validityDigests,
            deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : decoded.deviceKeyInfo,
        };
        __classPrivateFieldSet(this, _IssuerAuth_decodedPayload, result, "f");
        return result;
    }
    get certificate() {
        if (typeof __classPrivateFieldGet(this, _IssuerAuth_certificate, "f") === 'undefined' && this.x5chain?.length) {
            __classPrivateFieldSet(this, _IssuerAuth_certificate, new x509_1.X509Certificate(this.x5chain[0]), "f");
        }
        return __classPrivateFieldGet(this, _IssuerAuth_certificate, "f");
    }
    get countryName() {
        return this.certificate?.issuerName.getField('C')[0];
    }
    get stateOrProvince() {
        return this.certificate?.issuerName.getField('ST')[0];
    }
    static async sign(protectedHeaders, unprotectedHeaders, payload, key) {
        const sign1 = await cose_kit_1.Sign1.sign(protectedHeaders, unprotectedHeaders, payload, key);
        return new IssuerAuth(sign1.protectedHeaders, sign1.unprotectedHeaders, sign1.payload, sign1.signature);
    }
}
_IssuerAuth_decodedPayload = new WeakMap(), _IssuerAuth_certificate = new WeakMap();
exports.default = IssuerAuth;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSXNzdWVyQXV0aC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tZG9jL21vZGVsL0lzc3VlckF1dGgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7QUFBQSx1Q0FBdUU7QUFDdkUseUNBQWlEO0FBRWpELHFDQUF3QztBQUN4QyxrREFBK0M7QUFHL0M7OztHQUdHO0FBQ0gsTUFBcUIsVUFBVyxTQUFRLGdCQUFLO0lBSTNDLFlBQ0UsZUFBa0QsRUFDbEQsaUJBQXVDLEVBQ3ZDLE9BQW1CLEVBQ25CLFNBQXFCO1FBRXJCLEtBQUssQ0FBQyxlQUFlLEVBQUUsaUJBQWlCLEVBQUUsT0FBTyxFQUFFLFNBQVMsQ0FBQyxDQUFDO1FBVGhFLDZDQUFxQjtRQUNyQiwwQ0FBOEI7SUFTOUIsQ0FBQztJQUVELElBQVcsY0FBYztRQUN2QixJQUFJLHVCQUFBLElBQUksa0NBQWdCLEVBQUU7WUFBRSxPQUFPLHVCQUFBLElBQUksa0NBQWdCLENBQUM7U0FBRTtRQUMxRCxJQUFJLE9BQU8sR0FBRyxJQUFBLGlCQUFVLEVBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ3ZDLE9BQU8sR0FBRyxPQUFPLFlBQVksbUJBQVEsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO1FBQy9ELE9BQU8sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1FBQ3RDLE1BQU0sZUFBZSxHQUFHLENBQUMsWUFBcUMsRUFBRSxFQUFFO1lBQ2hFLElBQUksQ0FBQyxZQUFZLEVBQUU7Z0JBQUUsT0FBTyxZQUFZLENBQUM7YUFBRTtZQUMzQyxPQUFPLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxHQUFHLFlBQVksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQyxFQUFFLEVBQUU7Z0JBQ3pFLE9BQU8sQ0FBQyxHQUFHLEVBQUUsS0FBSyxZQUFZLFVBQVUsQ0FBQyxDQUFDLENBQUMsSUFBQSxpQkFBVSxFQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN4RSxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ04sQ0FBQyxDQUFDO1FBQ0YsTUFBTSxNQUFNLEdBQVE7WUFDbEIsR0FBRyxPQUFPO1lBQ1YsWUFBWSxFQUFFLGVBQWUsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDO1lBQ25ELGVBQWUsRUFBRSxPQUFPLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLGVBQWU7WUFDaEgsYUFBYSxFQUFFLE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsYUFBYTtTQUN6RyxDQUFDO1FBQ0YsdUJBQUEsSUFBSSw4QkFBbUIsTUFBTSxNQUFBLENBQUM7UUFDOUIsT0FBTyxNQUFNLENBQUM7SUFDaEIsQ0FBQztJQUVELElBQVcsV0FBVztRQUNwQixJQUFJLE9BQU8sdUJBQUEsSUFBSSwrQkFBYSxLQUFLLFdBQVcsSUFBSSxJQUFJLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRTtZQUNwRSx1QkFBQSxJQUFJLDJCQUFnQixJQUFJLHNCQUFlLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFBLENBQUM7U0FDMUQ7UUFDRCxPQUFPLHVCQUFBLElBQUksK0JBQWEsQ0FBQztJQUMzQixDQUFDO0lBRUQsSUFBVyxXQUFXO1FBQ3BCLE9BQU8sSUFBSSxDQUFDLFdBQVcsRUFBRSxVQUFVLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ3ZELENBQUM7SUFFRCxJQUFXLGVBQWU7UUFDeEIsT0FBTyxJQUFJLENBQUMsV0FBVyxFQUFFLFVBQVUsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDeEQsQ0FBQztJQUVELE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUNmLGdCQUFrQyxFQUNsQyxrQkFBa0QsRUFDbEQsT0FBbUIsRUFDbkIsR0FBeUI7UUFFekIsTUFBTSxLQUFLLEdBQUcsTUFBTSxnQkFBSyxDQUFDLElBQUksQ0FBQyxnQkFBZ0IsRUFBRSxrQkFBa0IsRUFBRSxPQUFPLEVBQUUsR0FBRyxDQUFDLENBQUM7UUFDbkYsT0FBTyxJQUFJLFVBQVUsQ0FDbkIsS0FBSyxDQUFDLGdCQUFnQixFQUN0QixLQUFLLENBQUMsa0JBQWtCLEVBQ3hCLEtBQUssQ0FBQyxPQUFPLEVBQ2IsS0FBSyxDQUFDLFNBQVMsQ0FDaEIsQ0FBQztJQUNKLENBQUM7Q0FDRjs7a0JBL0RvQixVQUFVIn0=