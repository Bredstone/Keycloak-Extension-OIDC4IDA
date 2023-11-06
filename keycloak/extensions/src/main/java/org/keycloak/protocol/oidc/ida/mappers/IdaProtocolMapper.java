package org.keycloak.protocol.oidc.ida.mappers;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.ida.mappers.connector.IdaConnector;
import org.keycloak.protocol.oidc.ida.mappers.extractor.VerifiedClaimExtractor;
import org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidator;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.ValidationException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_REQUESTED_CLAIMS_WRONG_TYPE;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_VERIFIED_CLAIMS_MALFORMED;
import static org.keycloak.protocol.oidc.ida.mappers.IdaConstants.ERROR_MESSAGE_VERIFIED_CLAIMS_NOT_REQUESTED;
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
        // If external source will be used then validates it
        if (!Boolean.parseBoolean(mapperModel.getConfig().get(IDA_LOCAL_SOURCE_NAME))) {
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
        
        // If no claims were requested, there is nothing to do
        if (requestedString == null) {
            LOG.debug(ERROR_MESSAGE_REQUESTED_CLAIMS_EMPTY);
            
            return;
        }

        LOG.debugf("Requested claims string: %s", requestedString.replaceAll("\\s", ""));

        try {
            // Current token type (userinfo or id_token)
            String curEndpointKey = getEndpointKey(token.getType());

            // Parsing the requested claims to a JSON object
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
            mapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
            JsonNode requestedClaims = mapper.readTree(requestedString);
            JsonNode requestedToken = requestedClaims.get(curEndpointKey);

            // If the current token is not of a requested type, return
            if (requestedToken == null) {
                LOG.debugf(ERROR_MESSAGE_REQUESTED_CLAIMS_WRONG_TYPE, curEndpointKey);
            
                return;
            }

            // If there are no verified claims requested, return
            if (requestedToken.get(VERIFIED_CLAIMS) == null) {
                LOG.debug(ERROR_MESSAGE_VERIFIED_CLAIMS_NOT_REQUESTED);
            
                return;
            }

            // Validates the request using a JSON schema 
            VerifiedClaimsValidator.validateVerifiedClaimsRequest(requestedClaims);

            // Aqui é tudo teste
            JsonNode userVerifiedClaims = mapper.readTree(IdaProtocolMapper.class.getResourceAsStream("/user_claims.json"));
            VerifiedClaimExtractor.getVerifiedClaims(requestedToken, userVerifiedClaims);
        } catch (JsonProcessingException e) {
            LOG.warn(ERROR_MESSAGE_REQUESTED_CLAIMS_MALFORMED);

            return;
        } catch (GenerationException | ValidationException e) {
            LOG.warn(ERROR_MESSAGE_VERIFIED_CLAIMS_MALFORMED);
            LOG.warn(e.getMessage());

            return;
        } catch (IOException e) {
            // TODO Tirar isso daqui
            e.printStackTrace();
        }

        // if (!requestClaims.isEmpty()) {
        //     // Retrieving Verified Claims for a user from an external store
        //     IdaConnector idaConnector = keycloakSession.getProvider(IdaConnector.class);
        //     Map<String, Object> userAllClaims = idaConnector.getVerifiedClaims(mappingModel.getConfig(),
        //             userSession.getUser().getUsername());
        //     // Filtering request claims from validated claims in an external store
        //     List<Map<String, Object>> extractedClaims = new ArrayList<>();
        //     for (Map<String, Object> requestClaim : requestClaims) {
        //         Map<String, Object> extractedClaim = new VerifiedClaimExtractor(OffsetDateTime.now())
        //                 .getFilteredClaims(requestClaim, userAllClaims);
        //         extractedClaims.add(extractedClaim);
        //     }
        //     // Mapping filtering results to output
        //     mappingModel.getConfig().put(TOKEN_CLAIM_NAME, VERIFIED_CLAIMS);

        //     if (isArray(extractedClaims)) {
        //         // verified Claims is array.
        //         mappingModel.getConfig().put(ProtocolMapperUtils.MULTIVALUED, "true");
        //         OIDCAttributeMapperHelper.mapClaim(token, mappingModel, extractedClaims);
        //     } else {
        //         // verified Claims is single value.
        //         OIDCAttributeMapperHelper.mapClaim(token, mappingModel, extractedClaims.get(0));
        //     }
        // }
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