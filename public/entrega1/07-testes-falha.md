# Testes de falha

## Caso 1: retorno sem cookie temporário
- Preparação: login iniciado em uma janela comum; URL de autorização copiada e aberta em uma janela privativa sem o cookie __Host-oauth-tx.
- Pedido enviado: GET para /oauth/callback/google concluído na janela privativa, sem o cookie de transação.
- Resultado esperado: recusa da resposta, sem criação de sessão.
- Resultado observado: "Bad request"; nenhuma sessão foi criada.

## Caso 2: state alterado
- Preparação: início do login com Google capturado via DevTools (Network), com o Network aberto antes da navegação; o valor de state na URL de retorno (cabeçalho location/Request URL) foi alterado em um caractere.
- Pedido enviado: GET para /oauth/callback/google com o parâmetro state divergente do valor salvo no D1.
- Resultado esperado: recusa antes de trocar o código.
- Resultado observado: "Bad request"; /api/me respondeu {"error":"unauthorized"}.

## Caso 3: reutilização da transação
- Preparação: login completo e bem-sucedido com Google; a URL de callback usada foi capturada via DevTools (Network, Request URL).
- Pedido enviado: a mesma URL de callback (com o mesmo code e state já utilizados) foi reaberta em uma segunda aba.
- Resultado esperado: falha, pois a transação já foi removida.
- Resultado observado: "Bad request" na segunda tentativa; a sessão original (criada na primeira tentativa) permaneceu válida.

## Caso 4: sessão expirada
- Preparação: sessão válida ativa; no console do D1, executado UPDATE sessions SET expires_at = 0;.
- Pedido enviado: GET para /api/me com o cookie de sessão original, após a atualização no banco.
- Resultado esperado: /api/me responde 401.
- Resultado observado: {"error":"unauthorized"}, status 401.

## Caso 5: origem inválida na saída
- Preparação: sessão válida ativa; aberta uma aba em uma origem diferente (https://www.youtube.com).
- Pedido enviado: fetch("https://rodrigociorcero.pages.dev/oauth/logout", { method: "POST", credentials: "include" }) executado no console dessa outra origem.
- Resultado esperado: logout recusado; sessão original permanece válida.
- Resultado observado: pedido bloqueado por política de CORS ("No 'Access-Control-Allow-Origin' header is present") e resposta 403 (Forbidden); a sessão original continuou válida em /api/me.

## Caso 6: reutilização do cookie revogado
- Preparação: sessão válida ativa; valor do cookie __Host-session copiado via DevTools (Application > Cookies) antes do logout.
- Pedido enviado: logout realizado normalmente; em seguida, o valor antigo do cookie foi restaurado manualmente no navegador, e /api/me foi chamado novamente.
- Resultado esperado: /api/me responde 401 após o logout.
- Resultado observado: {"error":"unauthorized"}, status 401 — a linha da sessão já havia sido removida do D1 no logout.
