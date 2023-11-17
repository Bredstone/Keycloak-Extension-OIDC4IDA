package org.keycloak.connections.jpa.entityprovider;

import java.util.Collections;
import java.util.List;

/**
 * Dummy entity provider which loads a custom changelog xml file with liquibase 
 * db patches that adjust user attributes' length.
 */
public class UserAttributeJpaEntityProvider implements JpaEntityProvider {
    public static final String CHANGELOG_FILE = "META-INF/user-attribute-changelog-0.0.1.xml";

	@Override
	public List<Class<?>> getEntities() {
		return Collections.emptyList();
	}

	@Override
	public String getChangelogLocation() {
		return CHANGELOG_FILE;
	}

	@Override
	public String getFactoryId() {
		return UserAttributeJpaEntityProviderFactory.PROVIDER_ID;
	}

	@Override
	public void close() {
		// NOOP
	}
}
