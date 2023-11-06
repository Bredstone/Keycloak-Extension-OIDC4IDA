#!/bin/bash

valid_options=("run")
valid_extra_params=("--mvn-compile") # opcoes especiais devem conter o prefixo "--"

exec_option="$1"
service_name="$2"

if [[ "$exec_option" == "--help" ]]; then
    echo "Utilize o script da seguinte forma:"
    echo "dev.sh [run] (argumentos extras...)"
    echo ""
    echo "Colchetes indicam argumentos obrigatorios. Parenteses indicam opcionais."
    echo ""
    echo "Possiveis opcoes de execucao: ${valid_options[@]}"
    echo "Parametros extras validos: ${valid_extra_params[@]}"
    echo ""
    echo "Exemplos de chamada:"
    echo "dev.sh run"
    echo "dev.sh run --mvn-compile"

    exit 0
fi

if [[ ! " ${valid_options[@]} " =~ " ${exec_option} " ]]; then
    echo "Erro: o parametro 1 deve ser uma das opções válidas: ${valid_options[@]}"
    echo "Experimente executar dev.sh --help"
    exit 1
fi

# kill all containers
if [[ $(docker ps -q) ]]; then
    docker kill $(docker ps -q)
fi

if [[ $(docker ps -a -q) ]]; then
    docker rm $(docker ps -a -q)
fi

command=""

if [[ "$*" == *"--mvn-compile"* ]]; then
    echo "Compiling mvn package"
    eval "cd keycloak/extensions/ && mvn clean install && cd ../.."
fi

command="\
docker compose \
--env-file .env \
-f docker-compose.yml \
build --parallel \
&& \
docker compose \
--env-file .env \
-f docker-compose.yml \
up"

echo -e "Comando: \n$command"

eval "$command"
