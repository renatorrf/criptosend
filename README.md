# CriptoSend Backend

API Fastify/TypeScript do CriptoSend. O schema PostgreSQL é versionado por migrations e todos os nomes de schema são validados antes de uso.

## Desenvolvimento local

1. Copie `.env.example` para `.env` e preserve a conexão PostgreSQL existente.
2. Execute `npm run secrets:prepare` para preencher somente os segredos locais ausentes.
3. Execute `npm run db:migrate` e `npm run db:verify`.
4. Inicie com `npm run dev`.

Use Node.js 24.15 ou superior. O arquivo `.env` não deve ser commitado.

## Identidade e sessão

- O acesso principal usa nome de usuário e senha. O telefone é opcional, mutável e serve somente para localizar contatos.
- Quando informado, o telefone é normalizado para E.164, cifrado com AES-256-GCM e indexado por HMAC-SHA256.
- Senhas principais usam Argon2id e nunca são recuperáveis.
- O access token é curto e o refresh token é opaco, armazenado somente como hash e rotacionado a cada uso.
- O refresh token é entregue em cookie `HttpOnly`; em produção usa `Secure`, `SameSite=None` e particionamento para o frontend hospedado separadamente.
- A verificação telefônica legada aceita Twilio ou `PHONE_VERIFICATION_WEBHOOK_URL`. Sem provedor, somente essas rotas antigas respondem `PHONE_VERIFICATION_UNAVAILABLE`; o acesso por usuário e convite continua disponível.
- Números de homologação podem usar códigos fixos definidos somente no ambiente por `PHONE_VERIFICATION_TEST_CODES_JSON`. Apenas os telefones E.164 explicitamente mapeados deixam de chamar o provedor; a senha principal e os limites de tentativa continuam obrigatórios.
- As rotas de SMS permanecem somente durante a transição das contas legadas e podem ser removidas depois do corte operacional.

## Limite criptográfico do servidor

O backend armazena apenas chaves públicas de identidade, signed prekeys,
one-time prekeys e a chave pública de identidade de mídia de cada dispositivo.
As chaves privadas, a negociação de sessão e a cifra/decifra de mensagens e
mídia pertencem ao dispositivo cliente. O servidor nunca deve receber material
privado nem conteúdo em texto puro.

## Rotas disponíveis

- `POST /auth/register`, `/auth/verify`, `/auth/login`, `/auth/refresh`, `/auth/logout`
- `POST /auth/access/start`, `/auth/access/verify`, `/auth/access/register`, `/auth/access/login`
- `POST /auth/username/login`, `/auth/invitations/redeem`
- `POST /auth/username/recovery/start`, `/auth/username/recovery/complete`
- `GET|POST /management/invitations`, `DELETE /management/invitations/:id`
- `GET /management/users`, `PATCH /management/users/:id/status`
- `PATCH /me/phone`
- `PATCH /me/password`
- `POST /auth/recovery/password`, `/auth/recovery/admin-request`, `/auth/recovery/admin-status`, `/auth/recovery/admin-complete`
- `GET /me`
- `GET /devices`, `DELETE /devices/:id`
- `POST /keys/prekeys`, `GET /keys/:userId/bundle`
- `PUT /keys/media-identity`, `GET /keys/users/:userId/media-identities`
- `POST /users/lookup`
- `GET /conversations`, `POST /conversations/direct`, `GET /conversations/:id`
- `GET|POST /conversations/:id/messages`, `DELETE /messages/:id`
- `POST /messages/:id/delivered`, `POST /messages/:id/read`
- `GET /messages/:id/receipts`
- `GET /calls/ice-config`
- `GET /conversations/:id/calls`
- `GET /health`, `GET /ready`

O Socket.IO aceita somente WebSocket e exige `auth.token` com o mesmo access token da API. A identidade é derivada do token; rooms de conversa exigem membership validado no servidor.

Recibos de leitura e indicadores de digitação ficam desativados por padrão e podem ser alterados em `PATCH /me`. Mensagens temporárias aceitam `expiresInSeconds`; um processo interno sobrescreve o ciphertext expirado e registra o evento sem conteúdo.

## Cadastro e recuperação

Para preparar o primeiro acesso do administrador:

```powershell
npm run admin:bootstrap -- admin "Administrador da plataforma"
```

O comando imprime um token de uso único válido por 24 horas e uma sugestão de
senha. Na opção **Primeiro acesso**, informe o token, o usuário e a senha que
deseja cadastrar. Um administrador com ativação pendente pode receber outro
token executando o mesmo comando. Um administrador já ativado permanece intacto.

A opção `--reset-existing` remove todas as contas e os dados operacionais do
schema configurado, incluindo conversas, sessões e convites, na mesma transação
que prepara a nova conta administrativa. O schema e as migrações são preservados.

O administrador gera um token para o gestor, que escolhe seu @usuário e sua
senha no primeiro acesso. Após a ativação, o gestor aparece no painel com seu
saldo de convites.
Cada gestor recebe 10 vagas inicialmente e convida somente usuários da sua
equipe. O convite de usuário reserva uma vaga por até 24 horas. O cadastro
consome a vaga, enquanto a expiração ou revogação libera a reserva.
Os tokens são de uso único e somente seus hashes ficam no banco.

O fluxo telefônico abaixo é legado e fica disponível apenas para migração:

```powershell
npm run admin:migrate-phone-user -- 34999999999 teste.9999
```

Esse comando preserva a conta, o telefone e o histórico, atribui um usuário e
imprime uma senha temporária. Sessões antigas são encerradas.

Para redefinir o acesso, o gestor gera um novo token para um usuário da sua
equipe. O administrador pode fazer o mesmo para um gestor. A pessoa usa
**Primeiro acesso** para escolher outra senha. A redefinição encerra as sessões,
limpa o histórico da conta e preserva seus vínculos com a rede.

## Chamadas de vídeo

Chamadas são WebRTC ponto a ponto e usam o Socket.IO apenas para autorização,
estado e sinalização. Os eventos do cliente são `call:start`, `call:accept`,
`call:decline`, `call:end`, `webrtc:key-offer`, `webrtc:key-answer`,
`webrtc:offer`, `webrtc:answer` e `webrtc:ice-candidate`. O servidor entrega os
eventos correspondentes somente ao outro participante autenticado da conversa
direta.

O banco persiste apenas participantes, horários, status e eventos de auditoria.
SDP, candidatos ICE e chaves públicas efêmeras são efêmeros, não têm coluna no
schema e são redigidos da telemetria. Uma conversa pode ter uma chamada ativa
por vez e um participante não pode iniciar outra chamada enquanto estiver
ocupado.

O cliente exige WebRTC Encoded Transforms e cifra cada frame de áudio e vídeo
com AES-256-GCM, usando chaves novas por chamada derivadas por ECDH P-256 e
HKDF. Não existe fallback silencioso para mídia sem essa camada. A primeira
associação de uma identidade remota usa TOFU; o código de segurança exibido na
chamada deve ser comparado fora do aplicativo no primeiro contato. Mudanças
posteriores na chave fixada bloqueiam a chamada.

`RTC_ICE_SERVERS_JSON` aceita servidores STUN/ICE estáticos. Em produção,
configure `RTC_TURN_URLS` e `RTC_TURN_SHARED_SECRET`; a rota
`GET /calls/ice-config` gera usuário e senha de curta duração compatíveis com o
TURN REST API do Coturn. O segredo compartilhado nunca é enviado ao cliente nem
deve entrar no repositório. Há um modelo operacional em `infra/coturn`.
"# criptosend" 
"# Cripto-Backend" 
"# Cripto-Backend" 
"# Cripto-Backend" 
"# Cripto-Backend" 
"# Cripto-Backend" 
"# criptosend" 
