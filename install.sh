#!/bin/bash

### Execute isso para inicializar seu ambiente de desenvolvimento ###

## /etc/hosts
### Adiciona o keycloak ao /etc/hosts
if ! grep -q keycloak "/etc/hosts"; then
    echo "Adicionando o keycloak ao /etc/hosts, precisamos de root"
    sudo -- sh -c -e "echo '127.0.0.1 keycloak' >> /etc/hosts"
fi