package org.keycloak.protocol.oidc.ida.mappers.util;

public class VerifiedClaimsValidatorConstants {
    // Configs and properties
    public static final String SCHEMA_PATH = "/schema/";
    public static final String REQUEST_SCHEMA_PATH = SCHEMA_PATH + "verified_claims_request.json";
    public static final String VERIFIED_CLAIMS_SCHEMA_PATH = SCHEMA_PATH + "verified_claims.json";

    // Error messages
    public static final String ERROR_MESSAGE_REQUEST_SCHEMA_NOT_FOUND = "The schema file for verified claims' request could not be found!";
    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_SCHEMA_NOT_FOUND = "The schema file for verified claims could not be found!";
}
