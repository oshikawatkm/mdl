"use strict";
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _IssuerSignedItem_dataItem, _IssuerSignedItem_isValid;
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssuerSignedItem = void 0;
const uncrypto_1 = require("uncrypto");
const cbor_1 = require("../cbor");
const DataItem_1 = require("../cbor/DataItem");
const buffer_utils_1 = require("../buffer_utils");
const utils_1 = require("./utils");
const MDL_NAMESPACE = 'org.iso.18013.5.1';
const supportedDigestAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];
class IssuerSignedItem {
    constructor(dataItem) {
        _IssuerSignedItem_dataItem.set(this, void 0);
        _IssuerSignedItem_isValid.set(this, void 0);
        __classPrivateFieldSet(this, _IssuerSignedItem_dataItem, dataItem, "f");
    }
    encode() {
        return __classPrivateFieldGet(this, _IssuerSignedItem_dataItem, "f").buffer;
    }
    get dataItem() {
        return __classPrivateFieldGet(this, _IssuerSignedItem_dataItem, "f");
    }
    get decodedData() {
        if (!__classPrivateFieldGet(this, _IssuerSignedItem_dataItem, "f").data.has('digestID')) {
            throw new Error('Invalid data item');
        }
        return __classPrivateFieldGet(this, _IssuerSignedItem_dataItem, "f").data;
    }
    get digestID() {
        return this.decodedData.get('digestID');
    }
    get random() {
        return this.decodedData.get('random');
    }
    get elementIdentifier() {
        return this.decodedData.get('elementIdentifier');
    }
    get elementValue() {
        return this.decodedData.get('elementValue');
    }
    async calculateDigest(alg) {
        const bytes = (0, cbor_1.cborEncode)(__classPrivateFieldGet(this, _IssuerSignedItem_dataItem, "f"));
        const result = await uncrypto_1.subtle.digest(alg, bytes);
        return result;
    }
    async isValid(nameSpace, { decodedPayload: { valueDigests, digestAlgorithm }, }) {
        if (typeof __classPrivateFieldGet(this, _IssuerSignedItem_isValid, "f") !== 'undefined') {
            return __classPrivateFieldGet(this, _IssuerSignedItem_isValid, "f");
        }
        if (!supportedDigestAlgorithms.includes(digestAlgorithm)) {
            __classPrivateFieldSet(this, _IssuerSignedItem_isValid, false, "f");
            return false;
        }
        const digest = await this.calculateDigest(digestAlgorithm);
        const digests = valueDigests.get(nameSpace);
        if (typeof digests === 'undefined') {
            return false;
        }
        const expectedDigest = digests.get(this.digestID);
        __classPrivateFieldSet(this, _IssuerSignedItem_isValid, expectedDigest &&
            (0, buffer_utils_1.areEqual)(new Uint8Array(digest), expectedDigest), "f");
        return __classPrivateFieldGet(this, _IssuerSignedItem_isValid, "f");
    }
    matchCertificate(nameSpace, { countryName, stateOrProvince }) {
        if (nameSpace !== MDL_NAMESPACE) {
            return undefined;
        }
        if (this.elementIdentifier === 'issuing_country') {
            return countryName === this.elementValue;
        }
        if (this.elementIdentifier === 'issuing_jurisdiction' && stateOrProvince) {
            return stateOrProvince === this.elementValue;
        }
        return undefined;
    }
    static create(digestID, elementIdentifier, elementValue) {
        const random = (0, utils_1.getRandomBytes)(32);
        const dataItem = DataItem_1.DataItem.fromData(new Map([
            ['digestID', digestID],
            ['elementIdentifier', elementIdentifier],
            ['elementValue', elementValue],
            ['random', random],
        ]));
        return new IssuerSignedItem(dataItem);
    }
}
exports.IssuerSignedItem = IssuerSignedItem;
_IssuerSignedItem_dataItem = new WeakMap(), _IssuerSignedItem_isValid = new WeakMap();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSXNzdWVyU2lnbmVkSXRlbS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9tZG9jL0lzc3VlclNpZ25lZEl0ZW0udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsdUNBQWtDO0FBQ2xDLGtDQUFxQztBQUNyQywrQ0FBNEM7QUFFNUMsa0RBQTJDO0FBQzNDLG1DQUF5QztBQUV6QyxNQUFNLGFBQWEsR0FBRyxtQkFBbUIsQ0FBQztBQUUxQyxNQUFNLHlCQUF5QixHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUtwRSxNQUFhLGdCQUFnQjtJQUkzQixZQUNFLFFBQThCO1FBSnZCLDZDQUFnQztRQUN6Qyw0Q0FBOEI7UUFLNUIsdUJBQUEsSUFBSSw4QkFBYSxRQUFRLE1BQUEsQ0FBQztJQUM1QixDQUFDO0lBRU0sTUFBTTtRQUNYLE9BQU8sdUJBQUEsSUFBSSxrQ0FBVSxDQUFDLE1BQU0sQ0FBQztJQUMvQixDQUFDO0lBRUQsSUFBVyxRQUFRO1FBQ2pCLE9BQU8sdUJBQUEsSUFBSSxrQ0FBVSxDQUFDO0lBQ3hCLENBQUM7SUFFRCxJQUFZLFdBQVc7UUFDckIsSUFBSSxDQUFDLHVCQUFBLElBQUksa0NBQVUsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBQyxFQUFFO1lBQ3hDLE1BQU0sSUFBSSxLQUFLLENBQUMsbUJBQW1CLENBQUMsQ0FBQztTQUN0QztRQUNELE9BQU8sdUJBQUEsSUFBSSxrQ0FBVSxDQUFDLElBQUksQ0FBQztJQUM3QixDQUFDO0lBRUQsSUFBVyxRQUFRO1FBQ2pCLE9BQU8sSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsVUFBVSxDQUFXLENBQUM7SUFDcEQsQ0FBQztJQUVELElBQVcsTUFBTTtRQUNmLE9BQU8sSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFlLENBQUM7SUFDdEQsQ0FBQztJQUVELElBQVcs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