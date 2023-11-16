package org.keycloak.protocol.oidc.ida.mappers;

public class IdaConstants {
    public static final String IDA_MAPPER_DISPLAY_TYPE = "OpenID Connect for Identity Assurance 1.0 (OIDC4IDA)";
    public static final String IDA_MAPPER_HELP_TEXT = "Adds Verified Claims to an OpenID Connect UserInfo response or an ID Token";

    public static final String IDA_LOCAL_SOURCE_NAME = "ida.local.source";
    public static final String IDA_LOCAL_SOURCE_LABEL = "IDA local source";
    public static final String IDA_LOCAL_SOURCE_HELP_TEXT = "Use Keycloak's local database as a source for verified claims?";

    public static final String USERINFO = "userinfo";
    public static final String VERIFIED_CLAIMS = "verified_claims";
    public static final String CLAIMS = "claims";

    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY = "The requested claims are empty.";
    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_TOKEN_TYPE = "No claims were requested for %s tokens.";
    public static final String ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED = "The requested claims are not in a valid JSON format.";

    public static final String ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_NOT_REQUESTED = "No verified claims were requested.";
    public static final String ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_MALFORMED = "The verified_claims object could not be validated using the JSON schema.";
    
    public static final String ERROR_MESSAGE_CLAIMS_EMPTY = "The claims sub-element isn't allowed to be empty.";

    public static final String ERROR_MESSAGE_USER_VERIFIED_CLAIMS_EMPTY = "The user's verified claims could not be found.";

    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_EMPTY = "The resulting verified_claims object was empty.";
}