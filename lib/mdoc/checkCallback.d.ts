export type VerificationAssessment = {
    status: 'PASSED' | 'FAILED' | 'WARNING';
    category: 'DOCUMENT_FORMAT' | 'DEVICE_AUTH' | 'ISSUER_AUTH' | 'DATA_INTEGRITY';
    check: string;
    reason?: string;
};
export type VerificationCallback = (item: VerificationAssessment) => void;
export type UserDefinedVerificationCallback = (item: VerificationAssessment, original: VerificationCallback) => void;
export declare const defaultCallback: VerificationCallback;
export declare const buildCallback: (callback?: UserDefinedVerificationCallback) => VerificationCallback;
export declare const onCatCheck: (onCheck: UserDefinedVerificationCallback, category: VerificationAssessment['category']) => (item: Omit<VerificationAssessment, 'category'>) => void;
