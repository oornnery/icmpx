# icmpx

Uma biblioteca Python para criar diagnósticos ICMP com sockets *raw*. A API atual privilegia blocos reutilizáveis em vez de empacotar ferramentas do sistema, permitindo compor pings, *probes* e rotas diretamente em Python.

## Recursos

- `Client` com *context manager* para abrir e fechar o socket ICMP com segurança
- `probe()` para medir um hop específico, `ping()` para séries de amostras e `traceroute()` para descobrir rotas
- Dataclasses ricas (`EchoResult`, `TracerouteResult`, `ReceivedPacket` e outras) prontas para pós-processamento
- *Reverse DNS* opcional por requisição
- Exceção `RawSocketPermissionError` com instruções de privilégio quando o socket não pode ser criado

## Pré-requisitos

- Python 3.14 ou superior (veja `pyproject.toml`)
- Ambiente Linux com permissão para abrir sockets ICMP *raw*

Conceda a permissão ao interpretador uma única vez:

```bash
sudo setcap cap_net_raw+ep "$(realpath $(which python))"
```

## Início rápido

Sincronize as dependências com uma ferramenta como `uv`:

```bash
uv sync
```

Execute qualquer script de exemplo:

```bash
uv run examples/ping.py
```

Ou explore o traceroute:

```bash
uv run examples/traceroute.py
```

## Exemplos de uso

### Loop de ping básico

```python
from icmpx import Client

with Client(timeout=1.5) as client:
    resultados = client.ping("8.8.8.8", count=3)
    for resultado in resultados:
        if resultado.error:
            print(f"{resultado.request.addr}: {resultado.error}")
        else:
            print(
                f"resposta de {resultado.reply.received_packet.ip_header.src_addr} "
                f"em {resultado.reply.rtt:.2f} ms"
            )
```

Cada `EchoResult` carrega a requisição original, um `EchoReply` com o RTT medido e eventuais erros ICMP recebidos.

### Fluxo de traceroute

```python
from icmpx import Client

with Client(resolve_dns_default=True) as client:
    trace = client.traceroute("1.1.1.1", probes=2)
    for hop in trace.hops:
        addr = hop.addr or "?"
        host = hop.hostname or "?"
        rtts = [
            f"{probe.rtt:.2f} ms" if probe.rtt != float("inf") else "timeout"
            for probe in hop.probes
        ]
        print(f"{hop.ttl:>2}: {addr:<16} {host:<32} {' '.join(rtts)}")
```

`Client.traceroute()` retorna um `TracerouteResult` com metadados por hop, incluindo *reverse DNS* opcional e todos os RTTs coletados.

## Scripts de exemplo

- `examples/ping.py` — caminho mais curto para enviar múltiplos echos ICMP
- `examples/traceroute.py` — descoberta hop a hop usando a API da biblioteca
- `examples/tui.py` — TUI experimental em Textual (depende de módulos em desenvolvimento)

Copie esses scripts como ponto de partida ou integre o `Client` diretamente em serviços existentes.

## Tratamento de erros

Se o interpretador não conseguir criar o socket *raw*, o `Client` lança `RawSocketPermissionError` com orientações sobre `CAP_NET_RAW`. Os timeouts aparecem como `EchoResult.error == "timeout"`, enquanto respostas ICMP preservam seus códigos para diagnóstico detalhado.

## Próximos passos

- Suporte a IPv6
- Multiping com agregação para múltiplos destinos
- Cliente compatível com `asyncio`
- Novos exemplos e documentação narrativa

Contribuições são bem-vindas — abra uma issue com sua necessidade ou ideia.
