import { ProtectedHeaders, Sign1, UnprotectedHeaders } from 'cose-kit';
import { X509Certificate } from '@peculiar/x509';
import { KeyLike } from 'jose';
import { MSO } from './types';
/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export default class IssuerAuth extends Sign1 {
    #private;
    constructor(protectedHeader: Map<number, unknown> | Uint8Array, unprotectedHeader: Map<number, unknown>, payload: Uint8Array, signature: Uint8Array);
    get decodedPayload(): MSO;
    get certificate(): X509Certificate;
    get countryName(): string;
    get stateOrProvince(): string;
    static sign(protectedHeaders: ProtectedHeaders, unprotectedHeaders: UnprotectedHeaders | undefined, payload: Uint8Array, key: KeyLike | Uint8Array): Promise<IssuerAuth>;
}
