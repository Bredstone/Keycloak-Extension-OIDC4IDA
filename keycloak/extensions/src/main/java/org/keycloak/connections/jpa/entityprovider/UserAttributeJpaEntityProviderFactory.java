package org.keycloak.connections.jpa.entityprovider;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Dummy entity provider which loads a custom changelog xml file with liquibase 
 * db patches that adjust user attributes' length.
 */
public class UserAttributeJpaEntityProviderFactory implements JpaEntityProviderFactory {
    public static final String PROVIDER_ID = "user-attribute-entity-provider";

    @Override
    public JpaEntityProvider create(KeycloakSession session) {
        return new UserAttributeJpaEntityProvider();
    }

    @Override
    public void init(Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
