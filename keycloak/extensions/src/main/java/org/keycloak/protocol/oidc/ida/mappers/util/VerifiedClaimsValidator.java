package org.keycloak.protocol.oidc.ida.mappers.util;

import java.io.IOException;
import java.net.URI;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Loader;
import net.jimblackler.jsonschemafriend.Schema;
import net.jimblackler.jsonschemafriend.SchemaStore;
import net.jimblackler.jsonschemafriend.ValidationException;
import net.jimblackler.jsonschemafriend.Validator;

import static net.jimblackler.jsonschemafriend.StreamUtils.streamToString;

import static org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidatorConstants.ERROR_MESSAGE_REQUEST_SCHEMA_NOT_FOUND; 
import static org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidatorConstants.ERROR_MESSAGE_VERIFIED_CLAIMS_SCHEMA_NOT_FOUND;
import static org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidatorConstants.REQUEST_SCHEMA_PATH;
import static org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidatorConstants.SCHEMA_PATH;
import static org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidatorConstants.VERIFIED_CLAIMS_SCHEMA_PATH;

public class VerifiedClaimsValidator {
    private static final Logger LOG = Logger.getLogger(VerifiedClaimsValidator.class);

    /**
     * Validates a JSON "verified_claims" object
     * 
     * @param verifiedClaims
     * @throws GenerationException
     * @throws ValidationException
     */
    public static void validateVerifiedClaims(JsonNode verifiedClaims) throws ValidationException, GenerationException {
        try {
            JsonNode schema = new ObjectMapper().readTree(VerifiedClaimsValidator.class.getResourceAsStream(VERIFIED_CLAIMS_SCHEMA_PATH));

            validateJson(verifiedClaims, schema);
        } catch (IOException e) {
        // This shouldn't happen

            LOG.error(ERROR_MESSAGE_VERIFIED_CLAIMS_SCHEMA_NOT_FOUND);
            e.printStackTrace();
        }
    }

    /**
     * Validates a JSON "verified_claims" request
     * 
     * @param requestedVerifiedClaims
     * @throws GenerationException
     * @throws ValidationException
     */
    public static void validateVerifiedClaimsRequest(JsonNode requestedVerifiedClaims) throws ValidationException, GenerationException {
        try {
            JsonNode schema = new ObjectMapper().readTree(VerifiedClaimsValidator.class.getResourceAsStream(REQUEST_SCHEMA_PATH));

            validateJson(requestedVerifiedClaims, schema);
        } catch (IOException e) {
        // This shouldn't happen

            LOG.error(ERROR_MESSAGE_REQUEST_SCHEMA_NOT_FOUND);
            e.printStackTrace();
        }
    }

    /**
     * Validates a JSON Object based on a schema
     * 
     * @param json
     * @param schema
     * @throws GenerationException
     * @throws ValidationException
     */
    private static void validateJson(JsonNode json, JsonNode schema) throws ValidationException, GenerationException {
        // This is a custom loader that retrieves the schemas being referenced through the resources' directory
        Loader resourcesLoader = new Loader() {
            @Override
            public String load(URI uri, boolean cacheSchema) throws IOException {
                // URI path
                String[] path = uri.getPath().split("/");
                String fileName = path[path.length - 1];

                // Load and return the specified file
                return streamToString(VerifiedClaimsValidator.class.getResourceAsStream(SCHEMA_PATH + fileName));
            }
        };

        // Load the schema and create a new validator
        SchemaStore schemaStore = new SchemaStore(resourcesLoader);
        Schema convertedSchema = schemaStore.loadSchemaJson(schema.toString());
        Validator validator = new Validator();

        // Validates the JSON
        validator.validateJson(convertedSchema, json.toString());
    }
}
