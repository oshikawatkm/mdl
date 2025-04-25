/// <reference types="node" />
import { Buffer } from 'buffer';
import { MDoc } from './model/MDoc';
import { DiagnosticInformation } from './model/types';
import { UserDefinedVerificationCallback } from './checkCallback';
export declare class Verifier {
    readonly issuersRootCertificates: string[];
    /**
     *
     * @param issuersRootCertificates The IACA root certificates list of the supported issuers.
     */
    constructor(issuersRootCertificates: string[]);
    private verifyIssuerSignature;
    private verifyDeviceSignature;
    private verifyData;
    /**
     * Parse and validate a DeviceResponse as specified in ISO/IEC 18013-5 (Device Retrieval section).
     *
     * @param encodedDeviceResponse
     * @param options.encodedSessionTranscript The CBOR encoded SessionTranscript.
     * @param options.ephemeralReaderKey The private part of the ephemeral key used in the session where the DeviceResponse was obtained. This is only required if the DeviceResponse is using the MAC method for device authentication.
     */
    verify(encodedDeviceResponse: Uint8Array, options?: {
        encodedSessionTranscript?: Uint8Array;
        ephemeralReaderKey?: Uint8Array;
        disableCertificateChainValidation?: boolean;
        onCheck?: UserDefinedVerificationCallback;
    }): Promise<MDoc>;
    getDiagnosticInformation(encodedDeviceResponse: Buffer, options: {
        encodedSessionTranscript?: Buffer;
        ephemeralReaderKey?: Buffer;
        disableCertificateChainValidation?: boolean;
    }): Promise<DiagnosticInformation>;
}
