# Guía técnica de TraceLens

## Recorrido del código

1. `PcapReader.read`: identifica el magic number (orden de bytes y precisión), limita tamaños, calcula el SHA-256 mientras lee y recorre los registros.
2. `PcapReader.decode`: quita la cabecera de enlace (Ethernet con VLAN, Linux SLL o IP sin enlace), valida IPv4 y lee las cabeceras TCP/UDP/ICMP. Clasifica cada registro en exactamente una categoría: decodificado, no IPv4, otro protocolo, malformado o fragmento.
3. `Analyzer.accept`: actualiza el flujo direccional y, solo para SYN sin ACK, la ventana del par origen/destino.
4. `Report`: genera HTML, CSV y JSON escapando siempre los valores.
5. `Main.run`: interpreta la línea de comandos y devuelve el código de salida (`System.exit` solo se llama en `main`, para poder probarlo).
6. `Fixtures` (en `test/`): genera las capturas sintéticas, con sumas de comprobación válidas, sin enviar tráfico.

## Preguntas de repaso

- ¿Por qué leer todos los enteros en el orden nativo del ordenador rompería algunos PCAP?
- ¿Qué diferencia hay entre longitud capturada, longitud original y bytes de aplicación?
- Si una captura usa `snaplen` 96, ¿por qué se pueden seguir decodificando las cabeceras? ¿Qué comprobación cambia?
- ¿Por qué un fragmento IPv4 no debe interpretarse como un segmento TCP completo?
- ¿Por qué un flujo de ida y otro de vuelta son dos entradas en esta implementación?
- ¿Por qué basta guardar la última hora de SYN por puerto para contar puertos distintos en la ventana? ¿Cuánta memoria usa como máximo un par?
- ¿Por qué los timestamps en nanosegundos se guardan como `long` y no como `double`?
- ¿Qué pasa si un paquete llega con un timestamp anterior al previo? ¿Por qué no se aborta el análisis?
- ¿Por qué muchos puertos distintos no demuestran un ataque? ¿Qué tráfico legítimo se parece?
- ¿Cómo evadiría esta regla un escaneo lento o distribuido?
- ¿Qué ocurre al llegar a 100.000 flujos y por qué es mejor que abortar?

## Próximo experimento

Construye tres escenarios sintéticos más con `Fixtures`: muchos puertos lentamente, muchas retransmisiones al mismo puerto y muchos puertos con SYN-ACK. Antes de ejecutarlos, anota qué debería ocurrir y por qué. Cambia `--threshold` y `--window` y guarda una tabla de resultados. No conviertas los resultados de unos ejemplos sintéticos en una tasa de precisión general.

## Posible ampliación

Implementa flujos bidireccionales canónicos con contadores separados por sentido. Especifica cómo normalizas la pareja IP/puerto, añade pruebas de tráfico inverso y compara los resultados con la vista Conversations de Wireshark. Documenta tu cambio y sus límites.
