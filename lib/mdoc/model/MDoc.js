"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MDoc = exports.MDocStatus = void 0;
const cbor_1 = require("../../cbor");
const IssuerSignedDocument_1 = require("./IssuerSignedDocument");
var MDocStatus;
(function (MDocStatus) {
    MDocStatus[MDocStatus["OK"] = 0] = "OK";
    MDocStatus[MDocStatus["GeneralError"] = 10] = "GeneralError";
    MDocStatus[MDocStatus["CBORDecodingError"] = 11] = "CBORDecodingError";
    MDocStatus[MDocStatus["CBORValidationError"] = 12] = "CBORValidationError";
})(MDocStatus || (exports.MDocStatus = MDocStatus = {}));
class MDoc {
    constructor(documents = [], version = '1.0', status = MDocStatus.OK, documentErrors = []) {
        this.documents = documents;
        this.version = version;
        this.status = status;
        this.documentErrors = documentErrors;
    }
    addDocument(document) {
        if (typeof document.issuerSigned === 'undefined') {
            throw new Error('Cannot add an unsigned document');
        }
        this.documents.push(document);
    }
    encode() {
        return (0, cbor_1.cborEncode)({
            version: this.version,
            documents: this.documents.map((doc) => doc.prepare()),
            status: this.status,
        });
    }
    static fromJSON(json) {
        const documents = json.documents.map((docJson) => {
            const auth = docJson.issuerSigned.issuerAuth;
            ['payload', 'signature', 'encodedProtectedHeaders'].forEach((key) => {
                if (auth[key]?.type === 'Buffer') {
                    auth[key] = Buffer.from(auth[key].data);
                }
            });
            auth.getContentForEncoding = function () {
                return {
                    protected: this.encodedProtectedHeaders,
                    unprotected: this.unprotectedHeaders,
                    payload: this.payload,
                    signature: this.signature,
                };
            };
            const issuerSigned = {
                ...docJson.issuerSigned,
                issuerAuth: auth,
            };
            return new IssuerSignedDocument_1.IssuerSignedDocument(docJson.docType, issuerSigned);
        });
        return new MDoc(documents);
    }
}
exports.MDoc = MDoc;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTURvYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tZG9jL21vZGVsL01Eb2MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscUNBQXdDO0FBQ3hDLGlFQUE4RDtBQVE5RCxJQUFZLFVBS1g7QUFMRCxXQUFZLFVBQVU7SUFDcEIsdUNBQU0sQ0FBQTtJQUNOLDREQUFpQixDQUFBO0lBQ2pCLHNFQUFzQixDQUFBO0lBQ3RCLDBFQUF3QixDQUFBO0FBQzFCLENBQUMsRUFMVyxVQUFVLDBCQUFWLFVBQVUsUUFLckI7QUFFRCxNQUFhLElBQUk7SUFDZixZQUNrQixZQUFvQyxFQUFFLEVBQ3RDLFVBQVUsS0FBSyxFQUNmLFNBQXFCLFVBQVUsQ0FBQyxFQUFFLEVBQ2xDLGlCQUFrQyxFQUFFO1FBSHBDLGNBQVMsR0FBVCxTQUFTLENBQTZCO1FBQ3RDLFlBQU8sR0FBUCxPQUFPLENBQVE7UUFDZixXQUFNLEdBQU4sTUFBTSxDQUE0QjtRQUNsQyxtQkFBYyxHQUFkLGNBQWMsQ0FBc0I7SUFDbEQsQ0FBQztJQUVMLFdBQVcsQ0FBQyxRQUE4QjtRQUN4QyxJQUFJLE9BQU8sUUFBUSxDQUFDLFlBQVksS0FBSyxXQUFXLEVBQUU7WUFDaEQsTUFBTSxJQUFJLEtBQUssQ0FBQyxpQ0FBaUMsQ0FBQyxDQUFDO1NBQ3BEO1FBQ0QsSUFBSSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsUUFBZ0MsQ0FBQyxDQUFDO0lBQ3hELENBQUM7SUFFRCxNQUFNO1FBQ0osT0FBTyxJQUFBLGlCQUFVLEVBQUM7WUFDaEIsT0FBTyxFQUFFLElBQUksQ0FBQyxPQUFPO1lBQ3JCLFNBQVMsRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsR0FBRyxDQUFDLE9BQU8sRUFBRSxDQUFDO1lBQ3JELE1BQU0sRUFBRSxJQUFJLENBQUMsTUFBTTtTQUNwQixDQUFDLENBQUM7SUFDTCxDQUFDO0lBRUgsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFTO1FBQ3ZCLE1BQU0sU0FBUyxHQUFHLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsT0FBWSxFQUFFLEVBQUU7WUFDcEQsTUFBTSxJQUFJLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUM7WUFFN0MsQ0FBQyxTQUFTLEVBQUUsV0FBVyxFQUFFLHlCQUF5QixDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUU7Z0JBQ2xFLElBQUksSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLElBQUksS0FBSyxRQUFRLEVBQUU7b0JBQ2hDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQztpQkFDekM7WUFDSCxDQUFDLENBQUMsQ0FBQztZQUVILElBQUksQ0FBQyxxQkFBcUIsR0FBRztnQkFDM0IsT0FBTztvQkFDTCxTQUFTLEVBQUUsSUFBSSxDQUFDLHVCQUF1QjtvQkFDdkMsV0FBVyxFQUFFLElBQUksQ0FBQyxrQkFBa0I7b0JBQ3BDLE9BQU8sRUFBRSxJQUFJLENBQUMsT0FBTztvQkFDckIsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTO2lCQUMxQixDQUFDO1lBQ0osQ0FBQyxDQUFDO1lBRUYsTUFBTSxZQUFZLEdBQUc7Z0JBQ25CLEdBQUcsT0FBTyxDQUFDLFlBQVk7Z0JBQ3ZCLFVBQVUsRUFBRSxJQUFJO2FBQ2pCLENBQUM7WUFFRixPQUFPLElBQUksMkNBQW9CLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxZQUFZLENBQUMsQ0FBQztRQUNqRSxDQUFDLENBQUMsQ0FBQztRQUVILE9BQU8sSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUM7SUFDN0IsQ0FBQztDQUVBO0FBckRELG9CQXFEQyJ9