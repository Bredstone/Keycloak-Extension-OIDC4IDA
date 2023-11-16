package org.keycloak.protocol.oidc.ida.mappers.connector;

public class IdaHttpConnectorConstants {
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_CONNECTION = "Could not connect to the IDA external store.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_JSON_STRUCTURE = "The user's verified_claims retrieved from the IDA external store are not in a valid json structure.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_NOT_SPECIFIED = "The IDA external source has not been specified.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_SCHEMA_VALIDATION = "The user's verified_claims retrieved from the IDA external store could not be validated using the JSON schema.";
}
