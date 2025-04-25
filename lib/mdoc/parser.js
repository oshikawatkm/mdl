"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = void 0;
const compare_versions_1 = require("compare-versions");
const cose_kit_1 = require("cose-kit");
const cbor_1 = require("../cbor");
const MDoc_1 = require("./model/MDoc");
const IssuerAuth_1 = __importDefault(require("./model/IssuerAuth"));
const IssuerSignedItem_1 = require("./IssuerSignedItem");
const errors_1 = require("./errors");
const IssuerSignedDocument_1 = require("./model/IssuerSignedDocument");
const DeviceSignedDocument_1 = require("./model/DeviceSignedDocument");
const parseIssuerAuthElement = (rawIssuerAuth, expectedDocType) => {
    const issuerAuth = new IssuerAuth_1.default(...rawIssuerAuth);
    const { decodedPayload } = issuerAuth;
    const { docType, version } = decodedPayload;
    if (docType !== expectedDocType) {
        throw new errors_1.MDLParseError(`The issuerAuth docType must be ${expectedDocType}`);
    }
    if (!version || (0, compare_versions_1.compareVersions)(version, '1.0') !== 0) {
        throw new errors_1.MDLParseError("The issuerAuth version must be '1.0'");
    }
    return issuerAuth;
};
const parseDeviceAuthElement = (rawDeviceAuth) => {
    const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth);
    if (deviceSignature) {
        return { deviceSignature: new cose_kit_1.Sign1(...deviceSignature) };
    }
    return { deviceMac: new cose_kit_1.Mac0(...deviceMac) };
};
const namespaceToArray = (entries) => {
    return entries.map((di) => new IssuerSignedItem_1.IssuerSignedItem(di));
};
const mapIssuerNameSpaces = (namespace) => {
    return Array.from(namespace.entries()).reduce((prev, [nameSpace, entries]) => {
        const mappedNamespace = namespaceToArray(entries);
        return {
            ...prev,
            [nameSpace]: mappedNamespace,
        };
    }, {});
};
const mapDeviceNameSpaces = (namespace) => {
    const entries = Array.from(namespace.entries()).map(([ns, attrs]) => {
        return [ns, Object.fromEntries(attrs.entries())];
    });
    return Object.fromEntries(entries);
};
/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
const parse = (encoded) => {
    let deviceResponse;
    try {
        deviceResponse = (0, cbor_1.cborDecode)(encoded);
    }
    catch (err) {
        throw new errors_1.MDLParseError(`Unable to decode device response: ${err.message}`);
    }
    const { version, documents, status } = Object.fromEntries(deviceResponse);
    const parsedDocuments = documents.map((doc) => {
        const issuerAuth = parseIssuerAuthElement(doc.get('issuerSigned').get('issuerAuth'), doc.get('docType'));
        const issuerSigned = doc.has('issuerSigned') ? {
            ...doc.get('issuerSigned'),
            nameSpaces: mapIssuerNameSpaces(doc.get('issuerSigned').get('nameSpaces')),
            issuerAuth,
        } : undefined;
        const deviceSigned = doc.has('deviceSigned') ? {
            ...doc.get('deviceSigned'),
            nameSpaces: mapDeviceNameSpaces(doc.get('deviceSigned').get('nameSpaces').data),
            deviceAuth: parseDeviceAuthElement(doc.get('deviceSigned').get('deviceAuth')),
        } : undefined;
        if (deviceSigned) {
            return new DeviceSignedDocument_1.DeviceSignedDocument(doc.get('docType'), issuerSigned, deviceSigned);
        }
        return new IssuerSignedDocument_1.IssuerSignedDocument(doc.get('docType'), issuerSigned);
    });
    return new MDoc_1.MDoc(parsedDocuments, version, status);
};
exports.parse = parse;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicGFyc2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL21kb2MvcGFyc2VyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLHVEQUFtRDtBQUNuRCx1Q0FBdUM7QUFDdkMsa0NBQXFDO0FBQ3JDLHVDQUFvQztBQUlwQyxvRUFBNEM7QUFDNUMseURBQXNEO0FBQ3RELHFDQUF5QztBQUN6Qyx1RUFBb0U7QUFDcEUsdUVBQW9FO0FBRXBFLE1BQU0sc0JBQXNCLEdBQUcsQ0FDN0IsYUFBNEIsRUFDNUIsZUFBdUIsRUFDWCxFQUFFO0lBQ2QsTUFBTSxVQUFVLEdBQUcsSUFBSSxvQkFBVSxDQUFDLEdBQUcsYUFBYSxDQUFDLENBQUM7SUFDcEQsTUFBTSxFQUFFLGNBQWMsRUFBRSxHQUFHLFVBQVUsQ0FBQztJQUN0QyxNQUFNLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBRSxHQUFHLGNBQWMsQ0FBQztJQUU1QyxJQUFJLE9BQU8sS0FBSyxlQUFlLEVBQUU7UUFDL0IsTUFBTSxJQUFJLHNCQUFhLENBQUMsa0NBQWtDLGVBQWUsRUFBRSxDQUFDLENBQUM7S0FDOUU7SUFFRCxJQUFJLENBQUMsT0FBTyxJQUFJLElBQUEsa0NBQWUsRUFBQyxPQUFPLEVBQUUsS0FBSyxDQUFDLEtBQUssQ0FBQyxFQUFFO1FBQ3JELE1BQU0sSUFBSSxzQkFBYSxDQUFDLHNDQUFzQyxDQUFDLENBQUM7S0FDakU7SUFFRCxPQUFPLFVBQVUsQ0FBQztBQUNwQixDQUFDLENBQUM7QUFFRixNQUFNLHNCQUFzQixHQUFHLENBQUMsYUFBNEIsRUFBYyxFQUFFO0lBQzFFLE1BQU0sRUFBRSxlQUFlLEVBQUUsU0FBUyxFQUFFLEdBQUcsTUFBTSxDQUFDLFdBQVcsQ0FBQyxhQUFhLENBQUMsQ0FBQztJQUN6RSxJQUFJLGVBQWUsRUFBRTtRQUNuQixPQUFPLEVBQUUsZUFBZSxFQUFFLElBQUksZ0JBQUssQ0FBQyxHQUFHLGVBQWUsQ0FBQyxFQUFFLENBQUM7S0FD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