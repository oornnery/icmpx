# icmpx

Uma biblioteca direta para explorar ICMP em Python. Com sockets e formatação via Rich, ela provê ping individual, multiping, traceroute e MTR com saídas prontas para leitura.

## Recursos

- Ping único com estatísticas de RTT
- Multiping com agregação de latências e perda
- Traceroute com resolução DNS opcional e múltiplas sondas
- MTR simplificado para acompanhar perda e jitter por hop

Pré-requisitos

- Python 3.14 ou superior (veja `pyproject.toml`)
- Permissão `CAP_NET_RAW` para abrir sockets ICMP

Conceda a permissão ao interpretador antes de executar:

```bash
sudo setcap cap_net_raw+ep "$(realpath $(which python))"
```

## Uso rápido

Sincronize as dependências (por exemplo, `uv sync`) e execute o script de demonstração:

```bash
uv run main.py
```

Ou execute o pacote diretamente:

```bash
uv run -m icmpx
```

O trecho central é enxuto (veja [`icmpx/main.py`](icmpx/main.py)):

```python
from icmpx import Icmp, console, mtr, multiping, traceroute

with Icmp() as icmp:
  ex1 = icmp.ping(target)
  console.print(ex1)
  ex2 = multiping(icmp, target)
  console.print(ex2)
  ex3 = traceroute(icmp, target, resolve_dns=True)
  console.print(ex3)
  ex4 = mtr(icmp, target, resolve_dns=True)
  console.print(ex4)

```

## Saída típica

```text
Reply from 8.8.8.8: time=7.92 ms (seq=1)

Multiping to 8.8.8.8 (8.8.8.8):
  Packets: Sent = 4, Received = 4, Lost = 0 (0.0% loss)
Approximate round trip times in milli-seconds:
  Minimum = 6.35 ms, Average = 16.54 ms, Maximum = 38.02 ms

Traceroute to 8.8.8.8 (8.8.8.8), 3 probes per hop
Hop  Address              Hostname                                     Probe Times (ms)
1    172.19.112.1         _gateway                                      0.34 ms      0.81 ms      0.43 ms
2    192.168.15.1                                                      8.53 ms      5.83 ms      3.32 ms
3    132.37.127.7         ip-132.37.127.7.user.vivozap.com.br          11.59 ms     11.37 ms     10.68 ms
4    201.1.228.105        201-1-228-105.dsl.telesp.net.br              10.46 ms      5.17 ms      4.21 ms
5    187.100.196.140      187-100-196-140.dsl.telesp.net.br             5.76 ms     10.28 ms     12.29 ms
6    ?                    ?                                           * timeout    * timeout    * timeout
7    72.14.220.222        ?                                            11.88 ms      6.75 ms     11.34 ms
8    172.253.69.243       ?                                            10.89 ms      8.39 ms      9.58 ms
9    108.170.248.215      ?                                             8.76 ms      8.01 ms     11.52 ms
10   8.8.8.8              dns.google                                    9.67 ms     10.80 ms     18.86 ms


MTR to 8.8.8.8 (8.8.8.8), 5 cycles
Hop  Address              Hostname                                  Loss%  Sent  Recv      Min      Avg      Max
1    172.19.112.1         _gateway                                    0.0     5     5     0.34     0.42     0.51
2    192.168.15.1                                                     0.0     5     5     3.37     3.90     4.35
3    132.37.127.7         ip-132.37.127.7.user.vivozap.com.br         0.0     5     5     5.58     8.82    11.36
4    201.1.228.105        201-1-228-105.dsl.telesp.net.br             0.0     5     5     4.35    11.89    23.09
5    187.100.196.140      187-100-196-140.dsl.telesp.net.br           0.0     5     5     5.70     9.45    14.64
6    ?                    ?                                         100.0     5     0        ?        ?        ?
7    72.14.220.222        ?                                           0.0     5     5     6.98    14.91    39.26
8    172.253.69.243       ?                                           0.0     5     5     8.00    11.41    14.07
9    108.170.248.215      ?                                           0.0     5     5    10.10    18.15    41.16
10   8.8.8.8              dns.google                                  0.0     5     5     7.26     9.73    13.05
```

Explore [`icmpx/_icmp.py`](icmpx/_icmp.py), [`icmpx/_multiping.py`](icmpx/_multiping.py), [`icmpx/_traceroute.py`](icmpx/_traceroute.py) e [`icmpx/_mtr.py`](icmpx/_mtr.py) para ajustar timeouts, número de sondas e ciclos conforme sua necessidade.

## Funcionalidades Futuras

- [ ] IPv6
- [ ] Estatísticas avançadas (jitter, desvio padrão)
- [ ] Suporte assíncrono com `asyncio`
- [ ] Documentação abrangente
- [ ] Testes unitários
- [ ] Suporte a Windows
- [ ] Integração com SNMP para coleta de métricas adicionais
- [ ] Demo TUI com Textual

## Demo TUI com Textual

Execute a interface interativa com:

```bash
uv run icmpx/tui.py
```

A TUI concentra ping, multiping, traceroute e MTR em um menu lateral. Cada ferramenta roda em uma *worker thread*, o que mantém a interface fluida enquanto as tabelas recebem novos resultados.

Dica: use o botão de *follow* na tela de Ping para acompanhar automaticamente novas respostas ou desative-o para analisar linhas antigas.

![Demo TUI](docs/ping_tui.png)

### Inspiração

[icmplib](https://github.com/ValentinBELYN/icmplib.git)
