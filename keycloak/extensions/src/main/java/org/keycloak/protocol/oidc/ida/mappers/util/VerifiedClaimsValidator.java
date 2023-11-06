package org.keycloak.protocol.oidc.ida.mappers.util;

import java.io.IOException;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Schema;
import net.jimblackler.jsonschemafriend.SchemaStore;
import net.jimblackler.jsonschemafriend.ValidationException;
import net.jimblackler.jsonschemafriend.Validator;

public class VerifiedClaimsValidator {
    private static final Logger LOG = Logger.getLogger(VerifiedClaimsValidator.class);

    /**
     * Validates a JSON verified claims request
     * 
     * @param requestedVerifiedClaims
     * @throws GenerationException
     * @throws ValidationException
     */
    public static void validateVerifiedClaimsRequest(JsonNode requestedVerifiedClaims) throws ValidationException, GenerationException {
        try {
            JsonNode schema = new ObjectMapper().readTree(VerifiedClaimsValidator.class.getResourceAsStream("/schema/verified_claims_request.json"));

            validateJson(requestedVerifiedClaims, schema);
        } catch (IOException e) {
            // TODO Handle if this happens
            // This shouldn't happen
            LOG.error("Verified claims request's schema file not found!");

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
        SchemaStore schemaStore = new SchemaStore();
        Schema convertedSchema = schemaStore.loadSchemaJson(schema.toString());
        Validator validator = new Validator();

        validator.validateJson(convertedSchema, json.toString());
    }
}
