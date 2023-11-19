package org.keycloak.protocol.oidc.ida.mappers.util;

public class VerifiedClaimsValidatorConstants {
    // Configs and properties
    public static final String SCHEMA_PATH = "/schema/";
    public static final String REQUEST_SCHEMA_PATH = SCHEMA_PATH + "verified_claims_request.json";
    public static final String VERIFIED_CLAIMS_SCHEMA_PATH = SCHEMA_PATH + "verified_claims.json";

    // Error messages
    public static final String ERROR_MESSAGE_REQUEST_SCHEMA_NOT_FOUND = "Verified claims request's schema file not found!";
    public static final String ERROR_MESSAGE_VERIFIED_CLAIMS_SCHEMA_NOT_FOUND = "Verified claims' schema file not found!";
}
