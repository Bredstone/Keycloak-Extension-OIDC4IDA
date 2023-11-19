package org.keycloak.protocol.oidc.ida.mappers.connector;

public class IdaHttpConnectorConstants {
    // Configs and properties
    public static final String IDA_EXTERNAL_STORE_HELP_TEXT = "The URI of external store used by IDA (only if local source is disabled)";

    // Error messages
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_URL = "Invalid URI of IDA external store.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_CONNECTION_EXCEPTION = "Could not connect to the IDA external store.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_IVALID_JSON_ = "The user's verified_claims retrieved from the IDA external store are not in a valid json structure.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_URL_NOT_SPECIFIED = "The IDA external source has not been specified.";
    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_SCHEMA = "The user's verified_claims retrieved from the IDA external store could not be validated using the JSON schema.";
}
