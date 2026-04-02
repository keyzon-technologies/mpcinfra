Fluxo de Keygen - Ordem de Execução
1. Entrada da requisição
cmd/mpcinfra/main.go → runNode()

Inicializa a conexão NATS, banco de dados, peer registry e consumers
2. Recebimento do pedido
pkg/eventconsumer/keygen_consumer.go → handleKeygenEvent()

Consome mensagem do JetStream no tópico mpc.keygen_request.*
Valida assinatura e autorização do initiator
Publica no tópico interno mpc:generate
3. Processamento do evento
pkg/eventconsumer/event_consumer.go → handleKeyGenEvent()

Verifica a assinatura do initiator
Checa sessões duplicadas
Cria duas sessões em paralelo: ECDSA + EdDSA
Chama Init() em ambas
4. Inicialização das sessões
pkg/mpc/session.go → base da sessão

Assina tópicos NATS para mensagens broadcast e diretas
Chama WaitForPeersReady() — barreira de sincronização com todos os peers via NATS request/reply
5a. Protocolo EdDSA (mais simples)
pkg/mpc/eddsa_keygen_session.go


FROST DKG Round 1 → broadcast + p2p Shamir shares
FROST DKG Round 2 → broadcast de verification key shares
→ persistAndFinish()
5b. Protocolo ECDSA (dois estágios)
pkg/mpc/ecdsa_keygen_session.go

Fase 1 - FROST DKG:


Round 1 → broadcast + p2p Shamir shares para cada peer
Round 2 → broadcast de verification key shares
Fase 2 - DKLS19 Pair Setup (9 rounds por par de nós):


Rounds 1-9 por par Alice/Bob
  └─ Commitment, Schnorr proof, Oblivious Transfer (OT)
→ persistAndFinish()
6. Persistência e resultado
pkg/mpc/ecdsa_keygen_session.go → persistAndFinish()

Salva ECDSAKeygenData e EDDSAKeygenData no BadgerDB
Salva KeyInfo (participantes, threshold) no Consul
Publica resultado em mpc.mpc_keygen_result.{walletID} com as chaves públicas ECDSA e EdDSA


==============================================================


Diagrama resumido

GenerateKeyMessage (JetStream)
    ↓
keygen_consumer.go → verifica e repassa
    ↓
event_consumer.go → cria 2 sessões (ECDSA + EdDSA)
    ↓
session.go → WaitForPeersReady() (sincronização)
    ↓
   ECDSA                          EdDSA
   ecdsa_keygen_session.go        eddsa_keygen_session.go
   ├─ FROST DKG R1+R2             └─ FROST DKG R1+R2
   └─ DKLS19 Pairs R1→R9              ↓ persistAndFinish()
        ↓ persistAndFinish()
    ↓
BadgerDB + Consul + publica resultado
Comunicação entre nós
Broadcast → tópico keygen:broadcast:{ecdsa|eddsa}:{walletID} (assinado Ed25519)
Direto (P2P) → tópico keygen:direct:{ecdsa|eddsa}:{fromID}:{toID}:{walletID} (criptografado ECDH)
Transport → pkg/messaging/point2point.go e pkg/messaging/pubsub.go