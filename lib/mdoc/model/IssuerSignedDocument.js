"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssuerSignedDocument = void 0;
/**
 * Represents an issuer signed document.
 *
 * Note: You don't need instantiate this class.
 * This is the return type of the parser and the document.sign() method.
 */
class IssuerSignedDocument {
    constructor(docType, issuerSigned) {
        this.docType = docType;
        this.issuerSigned = issuerSigned;
    }
    /**
     * Create the structure for encoding a document.
     *
     * @returns {Map<string, any>} - The document as a map
     */
    prepare() {
        const docMap = new Map();
        docMap.set('docType', this.docType);
        docMap.set('issuerSigned', {
            nameSpaces: new Map(Object.entries(this.issuerSigned?.nameSpaces ?? {}).map(([nameSpace, items]) => {
                return [nameSpace, items.map((item) => item.dataItem)];
            })),
            issuerAuth: this.issuerSigned?.issuerAuth.getContentForEncoding(),
        });
        return docMap;
    }
    /**
     * Helper method to get the values in a namespace as a JS object.
     *
     * @param {string} namespace - The namespace to add.
     * @returns {Record<string, any>} - The values in the namespace as an object
     */
    getIssuerNameSpace(namespace) {
        const nameSpace = this.issuerSigned.nameSpaces[namespace];
        return Object.fromEntries(nameSpace.map((item) => [item.elementIdentifier, item.elementValue]));
    }
    /**
     * List of namespaces in the document.
     */
    get issuerSignedNameSpaces() {
        return Object.keys(this.issuerSigned.nameSpaces);
    }
}
exports.IssuerSignedDocument = IssuerSignedDocument;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSXNzdWVyU2lnbmVkRG9jdW1lbnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWRvYy9tb2RlbC9Jc3N1ZXJTaWduZWREb2N1bWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQTs7Ozs7R0FLRztBQUNILE1BQWEsb0JBQW9CO0lBQy9CLFlBQ2tCLE9BQWdCLEVBQ2hCLFlBQTBCO1FBRDFCLFlBQU8sR0FBUCxPQUFPLENBQVM7UUFDaEIsaUJBQVksR0FBWixZQUFZLENBQWM7SUFDeEMsQ0FBQztJQUVMOzs7O09BSUc7SUFDSCxPQUFPO1FBQ0wsTUFBTSxNQUFNLEdBQUcsSUFBSSxHQUFHLEVBQWUsQ0FBQztRQUN0QyxNQUFNLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDcEMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxjQUFjLEVBQUU7WUFDekIsVUFBVSxFQUFFLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLFlBQVksRUFBRSxVQUFVLElBQUksRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxTQUFTLEVBQUUsS0FBSyxDQUFDLEVBQUUsRUFBRTtnQkFDakcsT0FBTyxDQUFDLFNBQVMsRUFBRSxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztZQUN6RCxDQUFDLENBQUMsQ0FBQztZQUNILFVBQVUsRUFBRSxJQUFJLENBQUMsWUFBWSxFQUFFLFVBQVUsQ0FBQyxxQkFBcUIsRUFBRTtTQUNsRSxDQUFDLENBQUM7UUFDSCxPQUFPLE1BQU0sQ0FBQztJQUNoQixDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxrQkFBa0IsQ0FBQyxTQUFpQjtRQUNsQyxNQUFNLFNBQVMsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxTQUFTLENBQUMsQ0FBQztRQUMxRCxPQUFPLE1BQU0sQ0FBQyxXQUFXLENBQ3ZCLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLGlCQUFpQixFQUFFLElBQUksQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUNyRSxDQUFDO0lBQ0osQ0FBQztJQUVEOztPQUVHO0lBQ0gsSUFBSSxzQkFBc0I7UUFDeEIsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUM7SUFDbkQsQ0FBQztDQUNGO0FBMUNELG9EQTBDQyJ9