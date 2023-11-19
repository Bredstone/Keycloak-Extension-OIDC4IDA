package org.keycloak.protocol.oidc.ida.mappers.connector;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.ValidationException;

import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.ida.mappers.connector.spi.IdaConnector;
import org.keycloak.protocol.oidc.ida.mappers.util.VerifiedClaimsValidator;
import org.keycloak.provider.ProviderConfigProperty;

import java.io.IOException;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;

import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.ERROR_MESSAGE_IDA_EXTERNAL_STORE_CONNECTION_EXCEPTION;
import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_SCHEMA;
import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_URL;
import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.ERROR_MESSAGE_IDA_EXTERNAL_STORE_IVALID_JSON_;
import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.ERROR_MESSAGE_IDA_EXTERNAL_STORE_URL_NOT_SPECIFIED;
import static org.keycloak.protocol.oidc.ida.mappers.connector.IdaHttpConnectorConstants.IDA_EXTERNAL_STORE_HELP_TEXT;
import static org.keycloak.validate.validators.NotBlankValidator.MESSAGE_BLANK;
import static org.keycloak.validate.validators.UriValidator.MESSAGE_INVALID_URI;

/**
 * Connector that uses HTTP to retrieve validated claims from an external store
 */
public class IdaHttpConnector implements IdaConnector {
    private static final Logger LOG = Logger.getLogger(IdaHttpConnector.class);

    @Override
    public void addIdaExternalStore(List<ProviderConfigProperty> configProperties) {
        ProviderConfigProperty nameProperty = new ProviderConfigProperty();
        nameProperty.setName(IDA_EXTERNAL_STORE_NAME);
        nameProperty.setLabel(IDA_EXTERNAL_STORE_LABEL);
        nameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        nameProperty.setHelpText(IDA_EXTERNAL_STORE_HELP_TEXT);
        configProperties.add(nameProperty);
    }

    @Override
    public void validateIdaExternalStore(Map<String, String> protocolMapperConfig)
            throws ProtocolMapperConfigException {
        String externalStoreUrl = protocolMapperConfig.get(IDA_EXTERNAL_STORE_NAME);
        if (externalStoreUrl == null || externalStoreUrl.isEmpty()) {
        // If no URL was provided

            throw new ProtocolMapperConfigException(ERROR_MESSAGE_IDA_EXTERNAL_STORE_URL_NOT_SPECIFIED, MESSAGE_BLANK);
        }

        try {
            new URI(externalStoreUrl).toURL(); // Validating the URL
        } catch (Exception e) {
        // The URL provided is invalid

            throw new ProtocolMapperConfigException(ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_URL, MESSAGE_INVALID_URI, e);
        }
    }

    @Override
    public JsonNode getVerifiedClaims(Map<String, String> protocolMapperConfig, String userId) {
        String externalStoreUrl = protocolMapperConfig.get(IDA_EXTERNAL_STORE_NAME);
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            // Retrieving user's verified_claims object from the external store
            SimpleHttp request = SimpleHttp.doGet(externalStoreUrl + "?userId=" + userId, client);
            
            LOG.debugf("Retrieved verified claims from HTTP source: %s", request.asString());
            
            // Convert the verified_claims object to a JSON representation
            JsonNode verifiedClaims = request.asJson();
            // Validates the verified_claims object using a JSON schema
            VerifiedClaimsValidator.validateVerifiedClaims(verifiedClaims);

            return verifiedClaims;
        } catch (IOException e) {
        // If something went wrong during the verified_claims retrieving process
        // These errors should not concern client applications
        // However, they will be logged into Keycloak's terminal, so admin could be aware that something is wrong

            if (e instanceof UnknownHostException || e instanceof HttpHostConnectException) {
            // If the external store couldn't be found

                LOG.errorf(ERROR_MESSAGE_IDA_EXTERNAL_STORE_CONNECTION_EXCEPTION + " IDA External Store = '%s'", externalStoreUrl);
            } else if (e instanceof MismatchedInputException || e instanceof JsonParseException) {
            // If the user's verified_claims is not in a valid JSON structure

                LOG.errorf(ERROR_MESSAGE_IDA_EXTERNAL_STORE_IVALID_JSON_);
            }

            e.printStackTrace();
            return null;
        } catch (ValidationException | GenerationException e) {
        // If something went wrong during the verified_claims validation process
        // These errors should not concern client applications
        // However, they will be logged into Keycloak's terminal, so admin could be aware that something is wrong

            LOG.error(ERROR_MESSAGE_IDA_EXTERNAL_STORE_INVALID_SCHEMA);

            e.printStackTrace();
            return null;
        }
    }

    @Override
    public void close() {
        // NOOP
    }
}
