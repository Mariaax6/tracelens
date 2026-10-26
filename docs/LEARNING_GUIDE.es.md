# Cómo entender y defender TraceLens

## Recorrido del código

1. `PcapReader.read`: identifica magic, byte order y precisión temporal; limita tamaños; recorre registros y decodifica cabeceras.
2. `Analyzer.accept`: actualiza un flujo direccional y, solo para SYN sin ACK, actualiza la ventana de intentos.
3. `Main`: transforma los resultados en HTML/CSV/JSON.
4. `Demo`: genera paquetes sintéticos, incluidas sumas de comprobación, sin enviar tráfico.

## Preguntas de entrevista

- ¿Por qué leer todos los enteros en orden nativo del ordenador rompería algunos PCAP?
- ¿Qué diferencia hay entre longitud capturada, longitud original y bytes de aplicación?
- ¿Por qué un fragmento IPv4 no debe interpretarse como un segmento TCP completo?
- ¿Por qué un flujo de ida y otro de vuelta son dos entradas en esta implementación?
- ¿Cómo se elimina un puerto del contador cuando expira uno de varios intentos al mismo puerto?
- ¿Por qué no demuestra un ataque la presencia de muchos puertos distintos? ¿Qué tráfico legítimo se parece?
- ¿Cómo evadiría esta regla una exploración lenta o distribuida?
- ¿Qué limita realmente la memoria? ¿Y qué parte depende del número de flujos?

## Experimento propio sugerido

Construye tres escenarios sintéticos adicionales: muchos puertos lentamente; muchas retransmisiones al mismo puerto; muchos puertos con SYN-ACK. Antes de ejecutarlos, anota qué debería ocurrir y por qué. Cambia umbral/ventana y guarda una tabla de resultados. No conviertas resultados sobre unos ejemplos sintéticos en una tasa de precisión general.

## Ampliación con contenido técnico

Implementa flujos bidireccionales canónicos con contadores separados por sentido. Especifica cómo normalizas la pareja IP/puerto, añade pruebas de tráfico inverso y compara los resultados con la vista Conversations de Wireshark. Documenta tu cambio y sus límites.
