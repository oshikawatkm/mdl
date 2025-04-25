export type DataItemParams<T = any> = {
    data: T;
    buffer: Uint8Array;
} | {
    data: T;
} | {
    buffer: Uint8Array;
};
/**
 * DataItem is an extension defined https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
 *  > Sometimes it is beneficial to carry an embedded CBOR data item that is
 *  > not meant to be decoded immediately at the time the enclosing data item is being decoded.
 *
 * The idea of this class is to provide lazy encode and decode of cbor data.
 *
 * Due to a bug in the cbor-x library, we are eagerly encoding the data in the constructor.
 * https://github.com/kriszyp/cbor-x/issues/83
 *
 */
export declare class DataItem<T = any> {
    #private;
    constructor(params: DataItemParams<T>);
    get data(): T;
    get buffer(): Uint8Array;
    static fromData<T>(data: T): DataItem<T>;
}
