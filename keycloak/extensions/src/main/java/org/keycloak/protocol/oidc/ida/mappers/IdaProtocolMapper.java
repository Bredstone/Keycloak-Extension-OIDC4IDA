package org.keycloak.protocol.oidc.ida.mappers;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.ida.mappers.connector.spi.IdaConnector;
import org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidator;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;

import com.authlete.common.ida.DatasetExtractor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import jakarta.ws.rs.core.Response;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.ValidationException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.CLAIMS;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_INVALID_JSON;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_NOT_REQUESTED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_INVALID_SCHEMA;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_NOT_REQUESTED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_USER_VERIFIED_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_USER_VERIFIED_CLAIMS_INVALID_JSON;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_USER_VERIFIED_CLAIMS_INVALID_SCHEMA;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_VERIFIED_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.IDA_LOCAL_SOURCE_HELP_TEXT;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.IDA_LOCAL_SOURCE_LABEL;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.IDA_LOCAL_SOURCE_NAME;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.IDA_MAPPER_DISPLAY_TYPE;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.IDA_MAPPER_HELP_TEXT;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.USERINFO;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.VERIFIED_CLAIMS;
import static org.keycloak.protocol.oidc.utils.OIDCResponseType.ID_TOKEN;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_ID;

/**
 * Support an extension of OpenID Connect for providing Replying Parties with
 * Verified Claims about End-Users
 * https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html
 */
public class IdaProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper,
        UserInfoTokenMapper, EnvironmentDependentProviderFactory {
    private static final String PROVIDER_ID = "oidc-ida-mapper";
    private static final Logger LOG = Logger.getLogger(IdaProtocolMapper.class);

    // Provider configs
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, IdaProtocolMapper.class);

        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(IDA_LOCAL_SOURCE_NAME);
        property.setLabel(IDA_LOCAL_SOURCE_LABEL);
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText(IDA_LOCAL_SOURCE_HELP_TEXT);
        property.setDefaultValue(true);
        configProperties.add(property);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Adds external IDA source configs

        IdaConnector idaConnector = factory.create().getProvider(IdaConnector.class);
        idaConnector.addIdaExternalStore(configProperties);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return IDA_MAPPER_DISPLAY_TYPE;
    }

    @Override
    public String getHelpText() {
        return IDA_MAPPER_HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client,
            ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        if (!Boolean.parseBoolean(mapperModel.getConfig().get(IDA_LOCAL_SOURCE_NAME))) {
        // If external source will be used then validates it

            IdaConnector idaConnector = session.getProvider(IdaConnector.class);
            idaConnector.validateIdaExternalStore(mapperModel.getConfig());   
        }
    }

    @Override
    protected void setClaim(final IDToken token, final ProtocolMapperModel mappingModel,
            final UserSessionModel userSession, final KeycloakSession keycloakSession, 
            final ClientSessionContext clientSessionCtx) {
        // Obtaining requested claims
        AuthenticatedClientSessionModel acs = clientSessionCtx.getClientSession();
        String requestedString = acs.getNote(OIDCLoginProtocol.CLAIMS_PARAM);
        
        if (requestedString == null) {
        // If no claims were requested, then there is nothing to do

            LOG.debug(ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY);
            
            return;
        }

        LOG.debugf("Requested claims string: %s", requestedString.replaceAll("\\s", ""));

        try {
            // Parsing the requested claims to a JSON object
            ObjectMapper mapper = new ObjectMapper()
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
            JsonNode requestedClaims = mapper.readTree(requestedString);

            String curEndpointKey = getEndpointKey(token.getType()); // Current token type (userinfo or id_token)
            if (requestedClaims.get(curEndpointKey) == null) {
            // If the current token is not of a requested type, return

                LOG.debugf(ERROR_MESSAGE_REQUESTED_CLAIMS_NOT_REQUESTED, curEndpointKey);
            
                return;
            }

            // Gets the requested verified_claims JSON object
            JsonNode requestedVerifiedClaims = requestedClaims.get(curEndpointKey).get(VERIFIED_CLAIMS);

            if (requestedVerifiedClaims == null) {
            // If no verified claims were requested, return

                LOG.debug(ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_NOT_REQUESTED);
                
                return;
            }

            // Asserts that every "claims" sub-element is not null 
            assertClaimsNotEmpty(
                requestedVerifiedClaims.isArray() 
                    ? mapper.convertValue(requestedVerifiedClaims, List.class) 
                    : mapper.convertValue(requestedVerifiedClaims, Map.class));

            // Validates the request using a JSON schema 
            VerifiedClaimsValidator.validateVerifiedClaimsRequest(requestedClaims);

            JsonNode userVerifiedClaims = null;
            if (!Boolean.parseBoolean(mappingModel.getConfig().get(IDA_LOCAL_SOURCE_NAME))) {
            // Retrieves user's verified claims from external source

                IdaConnector idaConnector = keycloakSession.getProvider(IdaConnector.class); 
                userVerifiedClaims = idaConnector.getVerifiedClaims(mappingModel.getConfig(), userSession.getUser().getUsername());
            } else if (userSession.getUser() != null) {
            // Retrieves user's verified claims from keycloak's database

                userVerifiedClaims = getVerifiedClaimsFromUserAttribute(userSession.getUser());
            }

            if (userVerifiedClaims == null || userVerifiedClaims.get(VERIFIED_CLAIMS) == null) {
            // If the user's verified_claims object could not be retrieved
                
                LOG.debug(ERROR_MESSAGE_USER_VERIFIED_CLAIMS_EMPTY);

                return;
            }

            userVerifiedClaims = userVerifiedClaims.get(VERIFIED_CLAIMS);
            List<Map<String, Object>> extractedClaims = new ArrayList<Map<String, Object>>();
            extractClaims(
                requestedVerifiedClaims.isArray() 
                    ? mapper.convertValue(requestedVerifiedClaims, List.class) 
                    : mapper.convertValue(requestedVerifiedClaims, Map.class), 
                userVerifiedClaims.isArray() 
                    ? mapper.convertValue(userVerifiedClaims, List.class) 
                    : mapper.convertValue(userVerifiedClaims, Map.class), 
                extractedClaims);
            
            if (extractedClaims.isEmpty()) {
            // If the resulting verified claims object is null, return
                
                LOG.warn(ERROR_MESSAGE_VERIFIED_CLAIMS_EMPTY);

                return;
            }

            extractedClaims.forEach(entry -> LOG.debugf("Resulting verified claims object: %s", entry.toString()));

            // Adding the verified_claims property to token
            mappingModel.getConfig().put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, VERIFIED_CLAIMS);
            if (extractedClaims.size() > 1) {
            // If multiple verified_claims objects were extracted

                mappingModel.getConfig().put(ProtocolMapperUtils.MULTIVALUED, "true");
                OIDCAttributeMapperHelper.mapClaim(token, mappingModel, extractedClaims);
            } else {
            // If a single verified_claims object was extracted

                OIDCAttributeMapperHelper.mapClaim(token, mappingModel, extractedClaims.get(0));
            }
        } catch (JsonProcessingException e) {
        // The requested claims are not in a valid JSON format

            LOG.warn(ERROR_MESSAGE_REQUESTED_CLAIMS_INVALID_JSON);

            return;
        } catch (GenerationException | ValidationException e) {
        // The requested verified claims are not in a valid verified_claims JSON format

            LOG.warn(ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_INVALID_SCHEMA);
            LOG.warn(e.getMessage());

            return;
        }
    }

    /**
     * Try to extracts the verified_claims request from user's all verified claims set and put them into a list
     * 
     * @param request
     * @param userClaims
     * @param resultingList
     */
    @SuppressWarnings("unchecked")
    private void extractClaims(Object request, Object userClaims, List<Map<String, Object>> resultingList) {
        if (request instanceof List) {
        // If request object is a list

            ((List<Map<String,Object>>) request).forEach(entry -> extractClaims(entry, userClaims, resultingList));            
            return;
        }

        if (userClaims instanceof List) {
        // If userClaims object is a list

            ((List<Map<String,Object>>) userClaims).forEach(entry -> extractClaims(request, entry, resultingList));
            return;
        }

        // Extracts the claims
        Map<String, Object> extracted = 
            new DatasetExtractor().extract((Map<String, Object>) request, (Map<String, Object>) userClaims);

        if (extracted != null && !extracted.isEmpty()) {
        // If the claims were extracted succesfully

            resultingList.add(extracted); // Adds the claims to resultingList
        }
    }

    /**
     * Inspects each "verified_claims" object and assure that the "claims" sub-element is not empty
     * 
     * @param verifiedClaims
     */
    @SuppressWarnings("unchecked")
    private void assertClaimsNotEmpty(Object verifiedClaims) {
        if (verifiedClaims instanceof List) {
        // If the verifiedClaims object is a list
            
            ((List<Map<String, Object>>) verifiedClaims).forEach(entry -> assertClaimsNotEmpty(entry));
            return;
        }

        Object claims = ((Map<String, Object>) verifiedClaims).get(CLAIMS);

        if (claims != null && claims instanceof Map && ((Map<String, Object>) claims).isEmpty()) {
        // If the claims sub-element is empty, abort the transaction with an invalid_request error

            LOG.debug(ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_CLAIMS_EMPTY);
            
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, 
                ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_CLAIMS_EMPTY, 
                Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Gets the endpoint key for the current request, based on its token type
     * 
     * @param tokenType
     * @return
     */
    private String getEndpointKey(String tokenType) {
        if (tokenType == null)
            return USERINFO;

        switch (tokenType) {
            case TOKEN_TYPE_ID:
            case TOKEN_TYPE_BEARER:
                return ID_TOKEN;
            default:
                return null;
        }
    }

    /**
     * Gets the verified claims from user's attributes. The default verified claims attribute's name is 
     * "verified_claims". It should have a JSON string containing one or more verified claims elements. It is also 
     * possible to have multiple "verified_claims" attributes, each one with a different verified claims JSON.
     *   
     * @param user
     * @return
     */
    private JsonNode getVerifiedClaimsFromUserAttribute(UserModel user) {
        if (user.getFirstAttribute(VERIFIED_CLAIMS) == null) {
        // If the user does not have any verified claims registered

            return null;
        }

        // The JsonNode that will be returned
        ObjectMapper mapper = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
        ArrayNode userVerifiedClaims = mapper.createArrayNode();
        
        // Gets all user's verified_claims attributes
        List<String> verifiedClaimsStrings = user.getAttributeStream(VERIFIED_CLAIMS).collect(Collectors.toList());
        for (String verifiedClaimsString : verifiedClaimsStrings) {
        // For each verified_claim

            JsonNode verifiedClaims;

            try {
                // Parses the verified_claims string
                verifiedClaims = mapper.readTree(verifiedClaimsString);
                // Validates the verified_claims object using a JSON schema
                VerifiedClaimsValidator.validateVerifiedClaims(verifiedClaims);
            } catch (JsonProcessingException e) {
            // The verified_claims are not in a valid JSON format

                LOG.info(ERROR_MESSAGE_USER_VERIFIED_CLAIMS_INVALID_JSON);
                continue;
            } catch (ValidationException | GenerationException e) {
            // The verified_claims are not in a valid verified_claims object format

                LOG.info(ERROR_MESSAGE_USER_VERIFIED_CLAIMS_INVALID_SCHEMA);
                continue;
            }

            if (verifiedClaims.get(VERIFIED_CLAIMS) == null) {
            // If verified claims cannot be found

                continue;
            }

            if (verifiedClaims.get(VERIFIED_CLAIMS).isArray()) {
            // If the verified_claims is a array, add each element to userVerifiedClaims

                verifiedClaims.get(VERIFIED_CLAIMS).elements().forEachRemaining(entry -> userVerifiedClaims.add(entry));
            } else {
            // If the verified_claims is a single object, add it to userVerifiedClaims

                userVerifiedClaims.add(verifiedClaims.get(VERIFIED_CLAIMS));
            }
        }

        return mapper.createObjectNode().set(VERIFIED_CLAIMS, userVerifiedClaims);
    }

    @Override
    public boolean isSupported() {
        return true;
    }
}