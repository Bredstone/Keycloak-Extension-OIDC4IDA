package org.keycloak.protocol.oidc.ida.mappers.connector.spi;

import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;

/**
 * Connector that retrieves verified claims for a user from an external source
 */
public interface IdaConnector extends Provider {
    String IDA_EXTERNAL_STORE_NAME = "ida.external.store";
    String IDA_EXTERNAL_STORE_LABEL = "IDA external source's URL";

    /**
     * Add external store information to Protocolmapper
     *
     * @param configProperties
     */
    void addIdaExternalStore(List<ProviderConfigProperty> configProperties);

    /**
     * Validate the setting value of IDA External Store
     *
     * @param protocolMapperConfig
     * @throws ProtocolMapperConfigException If the setting value is incorrect
     */
    void validateIdaExternalStore(Map<String, String> protocolMapperConfig) throws ProtocolMapperConfigException;

    /**
     * Get the verified claims of a specified user from an external store
     *
     * @param protocolMapperConfig Information set for Protocolmapper
     * @param userId               Target User ID
     * @return verified claims retrieved from an external store or null, if no verified claims could be retrieved
     */
    JsonNode getVerifiedClaims(Map<String, String> protocolMapperConfig, String userId);
}