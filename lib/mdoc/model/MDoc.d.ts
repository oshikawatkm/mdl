/// <reference types="node" />
import { IssuerSignedDocument } from './IssuerSignedDocument';
export type ErrorCode = number;
export type ErrorItems = Record<string, ErrorCode>;
export type DocumentError = {
    DocType: ErrorCode;
};
export declare enum MDocStatus {
    OK = 0,
    GeneralError = 10,
    CBORDecodingError = 11,
    CBORValidationError = 12
}
export declare class MDoc {
    readonly documents: IssuerSignedDocument[];
    readonly version: string;
    readonly status: MDocStatus;
    readonly documentErrors: DocumentError[];
    constructor(documents?: IssuerSignedDocument[], version?: string, status?: MDocStatus, documentErrors?: DocumentError[]);
    addDocument(document: IssuerSignedDocument): void;
    encode(): Buffer;
    static fromJSONDocument(json: any): MDoc;
}
