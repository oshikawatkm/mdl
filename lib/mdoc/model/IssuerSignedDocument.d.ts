import { DocType, IssuerSigned } from './types';
/**
 * Represents an issuer signed document.
 *
 * Note: You don't need instantiate this class.
 * This is the return type of the parser and the document.sign() method.
 */
export declare class IssuerSignedDocument {
    readonly docType: DocType;
    readonly issuerSigned: IssuerSigned;
    constructor(docType: DocType, issuerSigned: IssuerSigned);
    /**
     * Create the structure for encoding a document.
     *
     * @returns {Map<string, any>} - The document as a map
     */
    prepare(): Map<string, any>;
    /**
     * Helper method to get the values in a namespace as a JS object.
     *
     * @param {string} namespace - The namespace to add.
     * @returns {Record<string, any>} - The values in the namespace as an object
     */
    getIssuerNameSpace(namespace: string): Record<string, any>;
    /**
     * List of namespaces in the document.
     */
    get issuerSignedNameSpaces(): string[];
}
