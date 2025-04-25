"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = void 0;
const compare_versions_1 = require("compare-versions");
const x509_1 = require("@peculiar/x509");
const jose_1 = require("jose");
const buffer_1 = require("buffer");
const cose_kit_1 = require("cose-kit");
const uncrypto_1 = __importDefault(require("uncrypto"));
const utils_1 = require("./utils");
const checkCallback_1 = require("./checkCallback");
const parser_1 = require("./parser");
const DeviceSignedDocument_1 = require("./model/DeviceSignedDocument");
const MDL_NAMESPACE = 'org.iso.18013.5.1';
const DIGEST_ALGS = {
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
    'SHA-512': 'sha512',
};
class Verifier {
    /**
     *
     * @param issuersRootCertificates The IACA root certificates list of the supported issuers.
     */
    constructor(issuersRootCertificates) {
        this.issuersRootCertificates = issuersRootCertificates;
    }
    async verifyIssuerSignature(issuerAuth, disableCertificateChainValidation, onCheckG) {
        const onCheck = (0, checkCallback_1.onCatCheck)(onCheckG, 'ISSUER_AUTH');
        const { certificate, countryName } = issuerAuth;
        const verificationKey = certificate ? (await (0, jose_1.importX509)(certificate.toString(), issuerAuth.algName)) : undefined;
        if (!disableCertificateChainValidation) {
            try {
                await issuerAuth.verifyX509Chain(this.issuersRootCertificates);
                onCheck({
                    status: 'PASSED',
                    check: 'Issuer certificate must be valid',
                });
            }
            catch (err) {
                onCheck({
                    status: 'FAILED',
                    check: 'Issuer certificate must be valid',
                    reason: err.message,
                });
            }
        }
        const verificationResult = verificationKey && await issuerAuth.verify(verificationKey);
        onCheck({
            status: verificationResult ? 'PASSED' : 'FAILED',
            check: 'Issuer signature must be valid',
        });
        // Validity
        const { validityInfo } = issuerAuth.decodedPayload;
        const now = new Date();
        onCheck({
            status: certificate && validityInfo && (validityInfo.signed < certificate.notBefore || validityInfo.signed > certificate.notAfter) ? 'FAILED' : 'PASSED',
            check: 'The MSO signed date must be within the validity period of the certificate',
            reason: `The MSO signed date (${validityInfo.signed.toUTCString()}) must be within the validity period of the certificate (${certificate.notBefore.toUTCString()} to ${certificate.notAfter.toUTCString()})`,
        });
        onCheck({
            status: validityInfo && (now < validityInfo.validFrom || now > validityInfo.validUntil) ? 'FAILED' : 'PASSED',
            check: 'The MSO must be valid at the time of verification',
            reason: `The MSO must be valid at the time of verification (${now.toUTCString()})`,
        });
        onCheck({
            status: countryName ? 'PASSED' : 'FAILED',
            check: 'Country name (C) must be present in the issuer certificate\'s subject distinguished name',
        });
    }
    async verifyDeviceSignature(document, options) {
        const onCheck = (0, checkCallback_1.onCatCheck)(options.onCheck, 'DEVICE_AUTH');
        if (!(document instanceof DeviceSignedDocument_1.DeviceSignedDocument)) {
            onCheck({
                status: 'FAILED',
                check: 'The document is not signed by the device.',
            });
            return;
        }
        const { deviceAuth, nameSpaces } = document.deviceSigned;
        const { docType } = document;
        const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
        const { deviceKey: deviceKeyCoseKey } = deviceKeyInfo || {};
        // Prevent cloning of the mdoc and mitigate man in the middle attacks
        if (!deviceAuth.deviceMac && !deviceAuth.deviceSignature) {
            onCheck({
                status: 'FAILED',
                check: 'Device Auth must contain a deviceSignature or deviceMac element',
            });
            return;
        }
        if (!options.sessionTranscriptBytes) {
            onCheck({
                status: 'FAILED',
                check: 'Session Transcript Bytes missing from options, aborting device signature check',
            });
            return;
        }
        const deviceAuthenticationBytes = (0, utils_1.calculateDeviceAutenticationBytes)(options.sessionTranscriptBytes, docType, nameSpaces);
        if (!deviceKeyCoseKey) {
            onCheck({
                status: 'FAILED',
                check: 'Issuer signature must contain the device key.',
                reason: 'Unable to verify deviceAuth signature: missing device key in issuerAuth',
            });
            return;
        }
        if (deviceAuth.deviceSignature) {
            const deviceKey = await (0, cose_kit_1.importCOSEKey)(deviceKeyCoseKey);
            // ECDSA/EdDSA authentication
            try {
                const ds = deviceAuth.deviceSignature;
                const verificationResult = await new cose_kit_1.Sign1(ds.protectedHeaders, ds.unprotectedHeaders, deviceAuthenticationBytes, ds.signature).verify(deviceKey);
                onCheck({
                    status: verificationResult ? 'PASSED' : 'FAILED',
                    check: 'Device signature must be valid',
                });
            }
            catch (err) {
                onCheck({
                    status: 'FAILED',
                    check: 'Device signature must be valid',
                    reason: `Unable to verify deviceAuth signature (ECDSA/EdDSA): ${err.message}`,
                });
            }
            return;
        }
        // MAC authentication
        onCheck({
            status: deviceAuth.deviceMac ? 'PASSED' : 'FAILED',
            check: 'Device MAC must be present when using MAC authentication',
        });
        if (!deviceAuth.deviceMac) {
            return;
        }
        onCheck({
            status: deviceAuth.deviceMac.hasSupportedAlg() ? 'PASSED' : 'FAILED',
            check: 'Device MAC must use alg 5 (HMAC 256/256)',
        });
        if (!deviceAuth.deviceMac.hasSupportedAlg()) {
            return;
        }
        onCheck({
            status: options.ephemeralPrivateKey ? 'PASSED' : 'FAILED',
            check: 'Ephemeral private key must be present when using MAC authentication',
        });
        if (!options.ephemeralPrivateKey) {
            return;
        }
        try {
            const ephemeralMacKey = await (0, utils_1.calculateEphemeralMacKey)(options.ephemeralPrivateKey, deviceKeyCoseKey, options.sessionTranscriptBytes);
            const isValid = await deviceAuth.deviceMac.verify(ephemeralMacKey, undefined, deviceAuthenticationBytes);
            onCheck({
                status: isValid ? 'PASSED' : 'FAILED',
                check: 'Device MAC must be valid',
            });
        }
        catch (err) {
            onCheck({
                status: 'FAILED',
                check: 'Device MAC must be valid',
                reason: `Unable to verify deviceAuth MAC: ${err.message}`,
            });
        }
    }
    async verifyData(mdoc, onCheckG) {
        // Confirm that the mdoc data has not changed since issuance
        const { issuerAuth } = mdoc.issuerSigned;
        const { valueDigests, digestAlgorithm } = issuerAuth.decodedPayload;
        const onCheck = (0, checkCallback_1.onCatCheck)(onCheckG, 'DATA_INTEGRITY');
        onCheck({
            status: digestAlgorithm && DIGEST_ALGS[digestAlgorithm] ? 'PASSED' : 'FAILED',
            check: 'Issuer Auth must include a supported digestAlgorithm element',
        });
        const nameSpaces = mdoc.issuerSigned.nameSpaces || {};
        await Promise.all(Object.keys(nameSpaces).map(async (ns) => {
            onCheck({
                status: valueDigests.has(ns) ? 'PASSED' : 'FAILED',
                check: `Issuer Auth must include digests for namespace: ${ns}`,
            });
            const verifications = await Promise.all(nameSpaces[ns].map(async (ev) => {
                const isValid = await ev.isValid(ns, issuerAuth);
                return { ev, ns, isValid };
            }));
            verifications.filter((v) => v.isValid).forEach((v) => {
                onCheck({
                    status: 'PASSED',
                    check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
                });
            });
            verifications.filter((v) => !v.isValid).forEach((v) => {
                onCheck({
                    status: 'FAILED',
                    check: `The calculated digest for ${ns}/${v.ev.elementIdentifier} attribute must match the digest in the issuerAuth element`,
                });
            });
            if (ns === MDL_NAMESPACE) {
                const issuer = issuerAuth.certificate.issuerName;
                if (!issuer) {
                    onCheck({
                        status: 'FAILED',
                        check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
                        reason: "The 'issuing_country' and 'issuing_jurisdiction' cannot be verified because the DS certificate was not provided",
                    });
                }
                else {
                    const invalidCountry = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_country')
                        .find((v) => !v.isValid || !v.ev.matchCertificate(ns, issuerAuth));
                    onCheck({
                        status: invalidCountry ? 'FAILED' : 'PASSED',
                        check: "The 'issuing_country' if present must match the 'countryName' in the subject field within the DS certificate",
                        reason: invalidCountry ?
                            `The 'issuing_country' (${invalidCountry.ev.elementValue}) must match the 'countryName' (${issuerAuth.countryName}) in the subject field within the issuer certificate` :
                            undefined,
                    });
                    const invalidJurisdiction = verifications.filter((v) => v.ns === ns && v.ev.elementIdentifier === 'issuing_jurisdiction')
                        .find((v) => !v.isValid || (issuerAuth.stateOrProvince && !v.ev.matchCertificate(ns, issuerAuth)));
                    onCheck({
                        status: invalidJurisdiction ? 'FAILED' : 'PASSED',
                        check: "The 'issuing_jurisdiction' if present must match the 'stateOrProvinceName' in the subject field within the DS certificate",
                        reason: invalidJurisdiction ?
                            `The 'issuing_jurisdiction' (${invalidJurisdiction.ev.elementValue}) must match the 'stateOrProvinceName' (${issuerAuth.stateOrProvince}) in the subject field within the issuer certificate` :
                            undefined,
                    });
                }
            }
        }));
    }
    /**
     * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
     *
     * @param encodedDeviceResponse
     * @param options.encodedSessionTranscript The CBOR encoded SessionTranscript.
     * @param options.ephemeralReaderKey The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
     */
    async verify(encodedDeviceResponse, options = {}) {
        const onCheck = (0, checkCallback_1.buildCallback)(options.onCheck);
        const dr = (0, parser_1.parse)(encodedDeviceResponse);
        onCheck({
            status: dr.version ? 'PASSED' : 'FAILED',
            check: 'Device Response must include "version" element.',
            category: 'DOCUMENT_FORMAT',
        });
        onCheck({
            status: (0, compare_versions_1.compareVersions)(dr.version, '1.0') >= 0 ? 'PASSED' : 'FAILED',
            check: 'Device Response version must be 1.0 or greater',
            category: 'DOCUMENT_FORMAT',
        });
        onCheck({
            status: dr.documents && dr.documents.length > 0 ? 'PASSED' : 'FAILED',
            check: 'Device Response must include at least one document.',
            category: 'DOCUMENT_FORMAT',
        });
        for (const document of dr.documents) {
            const { issuerAuth } = document.issuerSigned;
            await this.verifyIssuerSignature(issuerAuth, options.disableCertificateChainValidation, onCheck);
            await this.verifyDeviceSignature(document, {
                ephemeralPrivateKey: options.ephemeralReaderKey,
                sessionTranscriptBytes: options.encodedSessionTranscript,
                onCheck,
            });
            await this.verifyData(document, onCheck);
        }
        return dr;
    }
    async getDiagnosticInformation(encodedDeviceResponse, options) {
        const dr = [];
        const decoded = await this.verify(encodedDeviceResponse, {
            ...options,
            onCheck: (check) => dr.push(check),
        });
        const document = decoded.documents[0];
        const { issuerAuth } = document.issuerSigned;
        const issuerCert = issuerAuth.x5chain &&
            issuerAuth.x5chain.length > 0 &&
            new x509_1.X509Certificate(issuerAuth.x5chain[0]);
        const attributes = (await Promise.all(Object.keys(document.issuerSigned.nameSpaces).map(async (ns) => {
            const items = document.issuerSigned.nameSpaces[ns];
            return Promise.all(items.map(async (item) => {
                const isValid = await item.isValid(ns, issuerAuth);
                return {
                    ns,
                    id: item.elementIdentifier,
                    value: item.elementValue,
                    isValid,
                    matchCertificate: item.matchCertificate(ns, issuerAuth),
                };
            }));
        }))).flat();
        const deviceAttributes = document instanceof DeviceSignedDocument_1.DeviceSignedDocument ?
            Object.entries(document.deviceSigned.nameSpaces).map(([ns, items]) => {
                return Object.entries(items).map(([id, value]) => {
                    return {
                        ns,
                        id,
                        value,
                    };
                });
            }).flat() : undefined;
        let deviceKey;
        if (document?.issuerSigned.issuerAuth) {
            const { deviceKeyInfo } = document.issuerSigned.issuerAuth.decodedPayload;
            if (deviceKeyInfo?.deviceKey) {
                deviceKey = (0, cose_kit_1.COSEKeyToJWK)(deviceKeyInfo.deviceKey);
            }
        }
        const disclosedAttributes = attributes.filter((attr) => attr.isValid).length;
        const totalAttributes = Array.from(document
            .issuerSigned
            .issuerAuth
            .decodedPayload
            .valueDigests
            .entries()).reduce((prev, [, digests]) => prev + digests.size, 0);
        return {
            general: {
                version: decoded.version,
                type: 'DeviceResponse',
                status: decoded.status,
                documents: decoded.documents.length,
            },
            validityInfo: document.issuerSigned.issuerAuth.decodedPayload.validityInfo,
            issuerCertificate: issuerCert ? {
                subjectName: issuerCert.subjectName.toString(),
                pem: issuerCert.toString(),
                notBefore: issuerCert.notBefore,
                notAfter: issuerCert.notAfter,
                serialNumber: issuerCert.serialNumber,
                thumbprint: buffer_1.Buffer.from(await issuerCert.getThumbprint(uncrypto_1.default)).toString('hex'),
            } : undefined,
            issuerSignature: {
                alg: document.issuerSigned.issuerAuth.algName,
                isValid: dr
                    .filter((check) => check.category === 'ISSUER_AUTH')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'ISSUER_AUTH' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
                digests: Object.fromEntries(Array.from(document
                    .issuerSigned
                    .issuerAuth
                    .decodedPayload
                    .valueDigests
                    .entries()).map(([ns, digests]) => [ns, digests.size])),
            },
            deviceKey: {
                jwk: deviceKey,
            },
            deviceSignature: document instanceof DeviceSignedDocument_1.DeviceSignedDocument ? {
                alg: document.deviceSigned.deviceAuth.deviceSignature?.algName ??
                    document.deviceSigned.deviceAuth.deviceMac?.algName,
                isValid: dr
                    .filter((check) => check.category === 'DEVICE_AUTH')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'DEVICE_AUTH' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
            } : undefined,
            dataIntegrity: {
                disclosedAttributes: `${disclosedAttributes} of ${totalAttributes}`,
                isValid: dr
                    .filter((check) => check.category === 'DATA_INTEGRITY')
                    .every((check) => check.status === 'PASSED'),
                reasons: dr
                    .filter((check) => check.category === 'DATA_INTEGRITY' && check.status === 'FAILED')
                    .map((check) => check.reason ?? check.check),
            },
            attributes,
            deviceAttributes,
        };
    }
}
exports.Verifier = Verifier;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVmVyaWZpZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi9zcmMvbWRvYy9WZXJpZmllci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSx1REFBbUQ7QUFDbkQseUNBQWlEO0FBQ2pELCtCQUFnRDtBQUNoRCxtQ0FBZ0M7QUFDaEMsdUNBQThEO0FBQzlELHdEQUE4QjtBQUc5QixtQ0FHaUI7QUFLakIsbURBQXFIO0FBRXJILHFDQUFpQztBQUdqQyx1RUFBb0U7QUFFcEUsTUFBTSxhQUFhLEdBQUcsbUJBQW1CLENBQUM7QUFFMUMsTUFBTSxXQUFXLEdBQUc7SUFDbEIsU0FBUyxFQUFFLFFBQVE7SUFDbkIsU0FBUyxFQUFFLFFBQVE7SUFDbkIsU0FBUyxFQUFFLFFBQVE7Q0FDUyxDQUFDO0FBRS9CLE1BQWEsUUFBUTtJQUNuQjs7O09BR0c7SUFDSCxZQUE0Qix1QkFBaUM7UUFBakMsNEJBQXVCLEdBQXZCLHVCQUF1QixDQUFVO0lBQUksQ0FBQztJQUUxRCxLQUFLLENBQUMscUJBQXFCLENBQ2pDLFVBQXNCLEVBQ3RCLGlDQUEwQyxFQUMxQyxRQUF5QztRQUV6QyxNQUFNLE9BQU8sR0FBRyxJQUFBLDBCQUFVLEVBQUMsUUFBUSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1FBQ3BELE1BQU0sRUFBRSxXQUFXLEVBQUUsV0FBVyxFQUFFLEdBQUcsVUFBVSxDQUFDO1FBQ2hELE1BQU0sZUFBZSxHQUF3QixXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxJQUFBLGlCQUFVLEVBQzFFLFdBQVcsQ0FBQyxRQUFRLEVBQUUsRUFDdEIsVUFBVSxDQUFDLE9BQU8sQ0FDbkIsQ0FBQyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUM7UUFFZixJQUFJLENBQUMsaUNBQWlDLEVBQUU7WUFDdEMsSUFBSTtnQkFDRixNQUFNLFVBQVUsQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDLHVCQUF1QixDQUFDLENBQUM7Z0JBQy9ELE9BQU8sQ0FBQztvQkFD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