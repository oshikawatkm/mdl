import * as jose from 'jose';
import { DigestAlgorithm, DocType, SupportedAlgs, ValidityInfo } from './types';
import { IssuerSignedDocument } from './IssuerSignedDocument';
/**
 * Use this class when building new documents.
 *
 * This class allow you to build a document and sign it with the issuer's private key.
 */
export declare class Document {
    #private;
    readonly docType: DocType;
    constructor(doc?: DocType);
    private validateValues;
    /**
     * Add a namespace to an unsigned document.
     *
     * @param {string} namespace - The namespace to add.
     * @param {Record<string, any>} values - The values to add to the namespace.
     * @returns {Document} - The document
     */
    addIssuerNameSpace(namespace: 'org.iso.18013.5.1' | string, values: Record<string, any>): Document;
    /**
     * Get the values in a namespace.
     *
     * @param {string} namespace - The namespace to add.
     * @returns {Record<string, any>} - The values in the namespace as an object
     */
    getIssuerNameSpace(namespace: string): Record<string, any>;
    /**
     * Add the device public key which will be include in the issuer signature.
     * The device public key could be in JWK format or as COSE_Key format.
     *
     * @param params
     * @param {jose.JWK | Uint8Array} params.devicePublicKey - The device public key.
     */
    addDeviceKeyInfo({ deviceKey }: {
        deviceKey: jose.JWK | Uint8Array;
    }): Document;
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
    addValidityInfo(info?: Partial<ValidityInfo>): Document;
    /**
     * Set the digest algorithm used for the value digests in the issuer signature.
     *
     * The default is SHA-256.
     *
     * @param {DigestAlgorithm} digestAlgorithm - The digest algorithm to use.
     * @returns
     */
    useDigestAlgorithm(digestAlgorithm: DigestAlgorithm): Document;
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
    sign(params: {
        issuerPrivateKey: jose.JWK | Uint8Array;
        issuerCertificate: string | Uint8Array;
        alg: SupportedAlgs;
        kid?: string | Uint8Array;
    }): Promise<IssuerSignedDocument>;
}
