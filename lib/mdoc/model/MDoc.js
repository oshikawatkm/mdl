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
function deepRestoreBuffers(obj) {
    if (Array.isArray(obj)) {
        return obj.map(deepRestoreBuffers);
    }
    else if (obj && typeof obj === 'object') {
        if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
            return Buffer.from(obj.data);
        }
        for (const key of Object.keys(obj)) {
            obj[key] = deepRestoreBuffers(obj[key]);
        }
    }
    return obj;
}
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
    static fromJSONDocument(json) {
        // 再帰的に全体を Buffer に復元
        json.issuerSigned.issuerAuth = deepRestoreBuffers(json.issuerSigned.issuerAuth);
        // getContentForEncoding を復元
        json.issuerSigned.issuerAuth.getContentForEncoding = function () {
            return {
                protected: this.encodedProtectedHeaders,
                unprotected: this.unprotectedHeaders,
                payload: this.payload,
                signature: this.signature,
            };
        };
        const issuerSigned = {
            ...json.issuerSigned,
            issuerAuth: json.issuerSigned.issuerAuth,
        };
        const document = new IssuerSignedDocument_1.IssuerSignedDocument(json.docType, issuerSigned);
        return new MDoc([document]);
    }
}
exports.MDoc = MDoc;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTURvYy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tZG9jL21vZGVsL01Eb2MudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscUNBQXdDO0FBQ3hDLGlFQUE4RDtBQVE5RCxJQUFZLFVBS1g7QUFMRCxXQUFZLFVBQVU7SUFDcEIsdUNBQU0sQ0FBQTtJQUNOLDREQUFpQixDQUFBO0lBQ2pCLHNFQUFzQixDQUFBO0lBQ3RCLDBFQUF3QixDQUFBO0FBQzFCLENBQUMsRUFMVyxVQUFVLDBCQUFWLFVBQVUsUUFLckI7QUFFRCxTQUFTLGtCQUFrQixDQUFDLEdBQVE7SUFDbEMsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFFO1FBQ3RCLE9BQU8sR0FBRyxDQUFDLEdBQUcsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO0tBQ3BDO1NBQU0sSUFBSSxHQUFHLElBQUksT0FBTyxHQUFHLEtBQUssUUFBUSxFQUFFO1FBQ3pDLElBQUksR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLElBQUksS0FBSyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEVBQUU7WUFDcEQsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUM5QjtRQUNELEtBQUssTUFBTSxHQUFHLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRTtZQUNsQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsa0JBQWtCLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7U0FDekM7S0FDRjtJQUNELE9BQU8sR0FBRyxDQUFDO0FBQ2IsQ0FBQztBQUVELE1BQWEsSUFBSTtJQUNmLFlBQ2tCLFlBQW9DLEVBQUUsRUFDdEMsVUFBVSxLQUFLLEVBQ2YsU0FBcUIsVUFBVSxDQUFDLEVBQUUsRUFDbEMsaUJBQWtDLEVBQUU7UUFIcEMsY0FBUyxHQUFULFNBQVMsQ0FBNkI7UUFDdEMsWUFBTyxHQUFQLE9BQU8sQ0FBUTtRQUNmLFdBQU0sR0FBTixNQUFNLENBQTRCO1FBQ2xDLG1CQUFjLEdBQWQsY0FBYyxDQUFzQjtJQUNsRCxDQUFDO0lBRUwsV0FBVyxDQUFDLFFBQThCO1FBQ3hDLElBQUksT0FBTyxRQUFRLENBQUMsWUFBWSxLQUFLLFdBQVcsRUFBRTtZQUNoRCxNQUFNLElBQUksS0FBSyxDQUFDLGlDQUFpQyxDQUFDLENBQUM7U0FDcEQ7UUFDRCxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxRQUFnQyxDQUFDLENBQUM7SUFDeEQsQ0FBQztJQUVELE1BQU07UUFDSixPQUFPLElBQUEsaUJBQVUsRUFBQztZQUNoQixPQUFPLEVBQUUsSUFBSSxDQUFDLE9BQU87WUFDckIsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxHQUFHLENBQUMsT0FBTyxFQUFFLENBQUM7WUFDckQsTUFBTSxFQUFFLElBQUksQ0FBQyxNQUFNO1NBQ3BCLENBQUMsQ0FBQztJQUNMLENBQUM7SUFFRCxNQUFNLENBQUMsZ0JBQWdCLENBQUMsSUFBUztRQUMvQixxQkFBcUI7UUFDckIsSUFBSSxDQUFDLFlBQVksQ0FBQyxVQUFVLEdBQUcsa0JBQWtCLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQztRQUVoRiw0QkFBNEI7UUFDNUIsSUFBSSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMscUJBQXFCLEdBQUc7WUFDbkQsT0FBTztnQkFDTCxTQUFTLEVBQUUsSUFBSSxDQUFDLHVCQUF1QjtnQkFDdkMsV0FBVyxFQUFFLElBQUksQ0FBQyxrQkFBa0I7Z0JBQ3BDLE9BQU8sRUFBRSxJQUFJLENBQUMsT0FBTztnQkFDckIsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTO2FBQzFCLENBQUM7UUFDSixDQUFDLENBQUM7UUFFRixNQUFNLFlBQVksR0FBRztZQUNuQixHQUFHLElBQUksQ0FBQyxZQUFZO1lBQ3BCLFVBQVUsRUFBRSxJQUFJLENBQUMsWUFBWSxDQUFDLFVBQVU7U0FDekMsQ0FBQztRQUVGLE1BQU0sUUFBUSxHQUFHLElBQUksMkNBQW9CLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxZQUFZLENBQUMsQ0FBQztRQUN0RSxPQUFPLElBQUksSUFBSSxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUM5QixDQUFDO0NBR0Y7QUEvQ0Qsb0JBK0NDIn0=