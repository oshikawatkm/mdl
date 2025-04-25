import { cborEncode } from '../../cbor';
import { IssuerSignedDocument } from './IssuerSignedDocument';

export type ErrorCode = number;
export type ErrorItems = Record<string, ErrorCode>;
export type DocumentError = {
  DocType: ErrorCode;
};

export enum MDocStatus {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}

function deepRestoreBuffers(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(deepRestoreBuffers);
  } else if (obj && typeof obj === 'object') {
    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      return Buffer.from(obj.data);
    }
    for (const key of Object.keys(obj)) {
      obj[key] = deepRestoreBuffers(obj[key]);
    }
  }
  return obj;
}

export class MDoc {
  constructor(
    public readonly documents: IssuerSignedDocument[] = [],
    public readonly version = '1.0',
    public readonly status: MDocStatus = MDocStatus.OK,
    public readonly documentErrors: DocumentError[] = [],
  ) { }

  addDocument(document: IssuerSignedDocument) {
    if (typeof document.issuerSigned === 'undefined') {
      throw new Error('Cannot add an unsigned document');
    }
    this.documents.push(document as IssuerSignedDocument);
  }

  encode() {
    return cborEncode({
      version: this.version,
      documents: this.documents.map((doc) => doc.prepare()),
      status: this.status,
    });
  }

  static fromJSONDocument(json: any): MDoc {
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
  
    const document = new IssuerSignedDocument(json.docType, issuerSigned);
    return new MDoc([document]);
  }


}
