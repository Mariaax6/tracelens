# TraceLens

**Analizador de tráfico de red sin conexión, en Java 17.** Lee ficheros PCAP clásicos, agrupa los paquetes en flujos direccionales y señala patrones de muchos puertos TCP distintos con SYN en una ventana de tiempo. Además indica con contadores qué partes de la captura no se han podido analizar. Es un proyecto universitario de redes y seguridad defensiva.

No necesita librerías externas, drivers de captura, permisos de administrador ni conexión de red. Los PCAP incluidos son datos sintéticos de laboratorio con direcciones reservadas para documentación (RFC 5737).

[English README](README.md) · [Guía de aprendizaje](docs/LEARNING_GUIDE.es.md)

## Uso rápido

```sh
sh build.sh        # Linux/macOS (Windows: .\build.ps1 -JdkHome 'C:\Program Files\Java\jdk-21')
java -jar dist/tracelens.jar examples/demo.pcap reports/demo
```

Abre `reports/demo/report.html`. `flows.csv` contiene todos los flujos y `summary.json` sirve para automatizar.

```text
java -jar tracelens.jar <captura.pcap> <carpeta-informe> [opciones]

  --threshold <puertos>   Puertos SYN distintos que generan una alerta (2-65536, por defecto 12)
  --window <segundos>     Duración de la ventana deslizante (por defecto 10, máximo 86400)
  --html-rows <n>         Flujos mostrados en report.html (por defecto 500)
  --fail-on-alert         Termina con código 1 si hay alertas
  --version / -h, --help
```

Códigos de salida: **0** análisis completado · **1** hay alertas y se usó `--fail-on-alert` · **2** entrada inválida o error de uso.

Admite PCAP clásico (no PCAPNG) con Ethernet y VLAN, Linux SLL (`tcpdump -i any`) o IPv4 sin cabecera de enlace. Si tu captura es de Wireshark (PCAPNG), conviértela con `editcap -F pcap entrada.pcapng salida.pcap`. Captura solo en redes propias o en las que tengas autorización.

## Ejemplos

| Fichero | Qué muestra | Registros | Decodificados | Flujos | Alertas |
|---|---|---:|---:|---:|---:|
| `demo.pcap` | Ráfaga SYN a 16 puertos, más tráfico UDP e ICMP | 33 | 33 | 19 | 1 |
| `slow-diverse.pcap` | Control negativo: 20 puertos, separados 11 s | 20 | 20 | 20 | 0 |
| `coverage.pcap` | Captura SLL truncada con IPv6, ARP, fragmento, GRE, cabecera rota y un timestamp desordenado | 9 | 4 | 3 | 0 |

## Límites

Una alerta es una pista para investigar, no una prueba de ataque: hay tráfico legítimo que la dispara, y los escaneos lentos o distribuidos la evitan. No hay métricas de precisión ni de rendimiento medidas. No se analiza IPv6, PCAPNG, el contenido de los paquetes ni el reensamblado de fragmentos o flujos TCP. Todo lo que no se analiza se cuenta y aparece en el informe.

## Autoría

Desarrollado por Maria ([@Mariaax6](https://github.com/Mariaax6)). Publicado con [licencia MIT](LICENSE).
