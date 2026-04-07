Passo a passo — produção local
1. Gerar os certificados TLS

bash scripts/gen_certs.sh
Cria certs/ com CA, certs de servidor e cliente para NATS e Consul.

2. Subir infraestrutura com TLS

docker compose -f docker-compose.prod.yml up -d
NATS com mTLS na porta 4222
Consul com TLS HTTPS na porta 8501
3. Configurar o .env (ou exportar variáveis)

ENVIRONMENT=production
NATS_URL=tls://127.0.0.1:4222
NATS_TLS_CLIENT_CERT=./certs/nats-client.pem
NATS_TLS_CLIENT_KEY=./certs/nats-client.key
NATS_TLS_CA_CERT=./certs/rootCA.pem
CONSUL_ADDRESS=https://localhost:8501
CONSUL_TLS_CLIENT_CERT=./certs/consul-client.pem
CONSUL_TLS_CLIENT_KEY=./certs/consul-client.key
CONSUL_TLS_CA_CERT=./certs/rootCA.pem
BADGER_PASSWORD=<senha-forte>
BADGER_BACKUP_PASSWORD=<senha-diferente>
4. Gerar identidades com chaves criptografadas

mpcinfra-cli generate-initiator --node-name event_initiator --encrypt
bash setup_identities.sh   # gera node0/1/2 sem --encrypt
# para prod, gerar manualmente com --encrypt:
cd node0 && mpcinfra-cli generate-identity --node node0 --encrypt
5. Registrar peers e subir os nodes

mpcinfra-cli register-peers --peers peers.json
cd node0 && mpcinfra start -n node0
cd node1 && mpcinfra start -n node1
cd node2 && mpcinfra start -n node2