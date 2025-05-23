export type PresentationDefinitionField = {
    path: string[];
    intent_to_retain: boolean;
};
export type Format = {
    mso_mdoc: {
        alg: string[];
    };
};
export type InputDescriptor = {
    id: string;
    format: Format;
    constraints: {
        limit_disclosure: string;
        fields: PresentationDefinitionField[];
    };
};
export type PresentationDefinition = {
    id: string;
    input_descriptors: InputDescriptor[];
};
