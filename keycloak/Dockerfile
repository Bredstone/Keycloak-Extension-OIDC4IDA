# Compila o Keycloak
# Imagem do Keycloak
FROM quay.io/keycloak/keycloak:22.0.5

# Configura as variáveis de ambiente para o SPI de métricas
ENV KC_METRICS_ENABLED=true
ENV KC_FEATURES=token-exchange

# Copia os SPIs compilados previamente
COPY extensions/keycloak-oidc4ida.jar /opt/keycloak/providers

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
