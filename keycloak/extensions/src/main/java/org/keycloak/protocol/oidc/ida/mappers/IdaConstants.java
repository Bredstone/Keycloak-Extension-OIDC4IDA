package org.keycloak.protocol.oidc.ida.mappers;

public class IdaConstants {
    public static final String IDA_MAPPER_DISPLAY_TYPE = "OpenID Connect for Identity Assurance 1.0 (OIDC4IDA)";
    public static final String IDA_MAPPER_HELP_TEXT = "Adds Verified Claims to an OpenID Connect UserInfo response or an ID Token";

    public static final String IDA_LOCAL_SOURCE_NAME = "ida.local.source";
    public static final String IDA_LOCAL_SOURCE_LABEL = "IDA local source";
    public static final String IDA_LOCAL_SOURCE_HELP_TEXT = "Use Keycloak as a source for verified claims?";

    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY = "The requested claims are empty.";
    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_WRONG_TYPE = "No claims were requested for %s tokens.";
    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_NOT_REQUESTED = "No verified claims were requested.";
    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_MALFORMED = "The verified claims structure is not in a valid JSON schema.";
    public static final String ERROR_MESSAGE_CLAIMS_EMPTY = "The claims sub-element isn't allowed to be empty.";
    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_EMPTY = "The resulting verified claims object was empty.";
    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED = "The requested claims are not in a valid JSON format.";
    public static final String ERROR_MESSAGE_CONNECT_IDA_EXTERNAL_STORE_ERROR = "Could not connect to the IDA External Store.";

    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_JSON_SYNTAX_ERROR_ERROR = "The user claims of IDA external store have syntax error in json.";

    public static final String ERROR_MESSAGE_IDA_EXTERNAL_STORE_NOT_SPECIFIED = "The IDA External Store has not been specified.";

    public static final String USERINFO = "userinfo";
    public static final String VERIFIED_CLAIMS = "verified_claims";
    public static final String CLAIMS = "claims";
}