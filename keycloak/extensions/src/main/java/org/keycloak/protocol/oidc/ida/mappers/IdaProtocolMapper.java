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

import jakarta.ws.rs.core.Response;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.ValidationException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.CLAIMS;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_TOKEN_TYPE;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_MALFORMED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_NOT_REQUESTED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_USER_VERIFIED_CLAIMS_EMPTY;
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

            // Current token type (userinfo or id_token)
            String curEndpointKey = getEndpointKey(token.getType());
            if (requestedClaims.get(curEndpointKey) == null) {
            // If the current token is not of a requested type, return

                LOG.debugf(ERROR_MESSAGE_REQUESTED_CLAIMS_TOKEN_TYPE, curEndpointKey);
            
                return;
            }

            // The requested verified_claims JSON object
            JsonNode requestedVerifiedClaims = requestedClaims.get(curEndpointKey).get(VERIFIED_CLAIMS);

            if (requestedVerifiedClaims == null) {
            // If there were no verified claims requested, return

                LOG.debug(ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_NOT_REQUESTED);
                
                return;
            }

            if (requestedVerifiedClaims.isArray()) {
            // If multiple verified_claims objects were requested

                requestedVerifiedClaims.elements().forEachRemaining(entry -> assertClaimsNotEmpty(entry));
            } else {
            // If a single verified_claims objects was requested

                assertClaimsNotEmpty(requestedVerifiedClaims);
            }

            // Validates the request using a JSON schema 
            VerifiedClaimsValidator.validateVerifiedClaimsRequest(requestedClaims);

            final JsonNode[] userVerifiedClaims = { null };
            if (!Boolean.parseBoolean(mappingModel.getConfig().get(IDA_LOCAL_SOURCE_NAME))) {
            // If external source will be used then validates it

                IdaConnector idaConnector = keycloakSession.getProvider(IdaConnector.class); 
                userVerifiedClaims[0] = idaConnector.getVerifiedClaims(mappingModel.getConfig(), userSession.getUser().getUsername());
            } else {
                // TODO Pegar dos atributos do usuário
                userVerifiedClaims[0] = mapper.readTree(IdaProtocolMapper.class.getResourceAsStream("/user_claims.json"));
            }

            if (userVerifiedClaims[0] == null || userVerifiedClaims[0].get(VERIFIED_CLAIMS) == null) {
            // If the user's verified_claims object could not be retrieved
                
                LOG.debug(ERROR_MESSAGE_USER_VERIFIED_CLAIMS_EMPTY);

                return;
            }

            userVerifiedClaims[0] = userVerifiedClaims[0].get(VERIFIED_CLAIMS);
            List<Map<String, Object>> extractedClaims = new ArrayList<Map<String, Object>>();
            extractClaims(
                requestedVerifiedClaims.isArray() 
                    ? mapper.convertValue(requestedVerifiedClaims, List.class) 
                    : mapper.convertValue(requestedVerifiedClaims, Map.class), 
                userVerifiedClaims[0].isArray() 
                    ? mapper.convertValue(userVerifiedClaims[0], List.class) 
                    : mapper.convertValue(userVerifiedClaims[0], Map.class), 
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
            LOG.warn(ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED);

            return;
        } catch (GenerationException | ValidationException e) {
            LOG.warn(ERROR_MESSAGE_REQUESTED_VERIFIED_CLAIMS_MALFORMED);
            LOG.warn(e.getMessage());

            return;
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
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
     * Inspects each verified_claims object and assure that the claims sub-element is not empty
     * 
     * @param verifiedClaims
     */
    private void assertClaimsNotEmpty(JsonNode verifiedClaims) {
        if (verifiedClaims.get(CLAIMS) != null && verifiedClaims.get(CLAIMS).isObject() && verifiedClaims.get(CLAIMS).isEmpty()) {
        // If the claims sub-element is empty, abort the transaction with an invalid_request error

            LOG.debug(ERROR_MESSAGE_CLAIMS_EMPTY);
            
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, 
                ERROR_MESSAGE_CLAIMS_EMPTY, 
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

    @Override
    public boolean isSupported() {
        return true;
    }
}