import { DataItem } from '../cbor/DataItem';
import IssuerAuth from './model/IssuerAuth';
export type IssuerSignedDataItem = DataItem<Map<keyof IssuerSignedItem, unknown>>;
export declare class IssuerSignedItem {
    #private;
    constructor(dataItem: IssuerSignedDataItem);
    encode(): Uint8Array;
    get dataItem(): IssuerSignedDataItem;
    private get decodedData();
    get digestID(): number;
    get random(): Uint8Array;
    get elementIdentifier(): string;
    get elementValue(): any;
    calculateDigest(alg: Parameters<SubtleCrypto['digest']>[0]): Promise<ArrayBuffer>;
    isValid(nameSpace: string, { decodedPayload: { valueDigests, digestAlgorithm }, }: IssuerAuth): Promise<boolean>;
    matchCertificate(nameSpace: string, { countryName, stateOrProvince }: IssuerAuth): boolean | undefined;
    static create(digestID: number, elementIdentifier: string, elementValue: any): IssuerSignedItem;
}
