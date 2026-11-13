# Análisis de una conexión TLS real

> Informe de observación con fines educativos. Se observó una conexión HTTPS normal a un sitio público; no se hizo ningún escaneo ni prueba contra servidores ajenos.

## 1. Objetivo y alcance

Observar cómo se establece una conexión TLS real (versión negociada, algoritmos, certificado y cadena de confianza) y relacionar lo que se ve con los conceptos implementados en el kit: hashes, cifrado autenticado AES-GCM, firma digital y cadena de confianza.

Alcance: el handshake y los parámetros de seguridad. El contenido de la comunicación (datos de aplicación) **no** se puede ver, y se explica por qué en la sección 7.

## 2. Metodología

| Dato | Valor |
|---|---|
| Sitio observado | `example.org` (dominio reservado por IANA para ejemplos y documentación), puerto 443 |
| Fecha | 12 de noviembre de 2026 (OpenSSL) y 13 de noviembre de 2026 (captura de red), hora de Argentina |
| OpenSSL | 3.5.9 (29 Sep 2026), el que incluye Git for Windows |
| Wireshark / tshark | 4.6.9, sobre Npcap 1.90 (el controlador de captura de Windows) |
| Cálculo de huellas | `kit_cripto.hashing.sha256_archivo` (el módulo del kit) |
| Sistema | Windows 11, PowerShell |

Comandos usados (la salida cruda se guardó fuera del repositorio):

```
openssl s_client -connect example.org:443 -servername example.org -showcerts
openssl s_client -connect example.org:443 -servername example.org -tls1_2
openssl s_client -connect example.org:443 -servername example.org -tls1_3
openssl s_client -connect example.org:443 -servername example.org -tls1_3 -msg
openssl s_client -connect example.org:443 -servername example.org -tls1_3 -trace
openssl x509 -in servidor.pem -text -noout
openssl verify -show_chain -untrusted intermedios.pem servidor.pem
```

`-servername` envía el nombre del sitio en el ClientHello (SNI), necesario porque un mismo servidor puede alojar muchos dominios.

## 3. Resultados con OpenSSL

### 3.1 Parámetros negociados (conexión por defecto)

| Parámetro | Valor | Qué significa |
|---|---|---|
| Versión de TLS | **TLS 1.3** | El cliente ofreció 1.2 y 1.3; el servidor eligió la más nueva. |
| Cipher suite | `TLS_AES_256_GCM_SHA384` | Cifrado autenticado AES-256 en modo GCM; SHA-384 se usa en la derivación de claves (HKDF). |
| Grupo de intercambio de claves | **X25519MLKEM768** | Intercambio híbrido: combina X25519 (curva elíptica clásica) con ML-KEM-768 (resistente a computadoras cuánticas). |
| Firma del servidor (CertificateVerify) | `ecdsa_secp256r1_sha256` | El servidor demuestra que tiene la clave privada del certificado. |
| Compresión | Ninguna | |
| ALPN | No negociado | `s_client` no ofrece protocolos de aplicación; el navegador sí (`h2`, `http/1.1`). |
| Bytes del handshake | 5072 leídos, 1631 escritos | Mucho más que en TLS 1.2 por la clave post-cuántica (sección 5). |

### 3.2 Certificado del servidor

| Campo | Valor |
|---|---|
| Sujeto | `CN=example.org` |
| Nombres alternativos (SAN) | `example.org`, `*.example.org` |
| Emisor | `Cloudflare TLS Issuing ECC CA 3` (O=SSL Corporation) |
| Validez | 26 sep 2026 22:05 GMT → 25 dic 2026 22:13 GMT (unos 90 días) |
| Clave pública | EC, curva P-256 (256 bits) |
| Algoritmo de firma | `ecdsa-with-SHA256` |
| Es CA | No (`CA:FALSE`) |
| Uso de la clave | Solo firma digital; uso extendido: autenticación de servidor web |
| Transparencia de certificados | 2 SCT (Signed Certificate Timestamps) incluidos |
| Huella SHA-256 | `72:83:11:2E:A5:A8:B4:E6:E2:2A:4A:F5:87:C1:00:F6:08:67:73:E4:66:E7:AB:C0:F5:B3:42:63:50:C1:4C:9E` |

Notas:
- El **sujeto** es solo el nombre del sitio; los nombres válidos reales están en el SAN, que es lo que el navegador compara.
- La validez corta (~90 días) es habitual hoy: limita el daño si una clave se filtra.
- Los **SCT** prueban que el certificado se registró en logs públicos de Certificate Transparency, lo que permite detectar certificados emitidos indebidamente.

<details>
<summary>Salida de <code>openssl x509 -text -noout</code> (sin los bytes de la clave y la firma)</summary>

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0F:FB:C4:FB:A7:B8:B2:37:EC:FD:A4:BF:07:19:13:3F
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
        Validity
            Not Before: Sep 26 22:05:05 2026 GMT
            Not After : Dec 25 22:13:27 2026 GMT
        Subject: CN=example.org
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            Authority Information Access:
                CA Issuers - URI:http://i.cf-i.ssl.com/Cloudflare-TLS-I-E3.cer
                OCSP - URI:http://o.cf-i.ssl.com
            X509v3 Subject Alternative Name:
                DNS:example.org, DNS:*.example.org
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.38064.1.3.1.1
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://c.cf-i.ssl.com/ae801ed1c55bb579d79208b0d772acfb8cc3a208.crl
            X509v3 Key Usage: critical
                Digital Signature
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Timestamp : Sep 26 22:15:06.400 2026 GMT
                    Signature : ecdsa-with-SHA256
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Timestamp : Sep 26 22:15:06.427 2026 GMT
                    Signature : ecdsa-with-SHA256
    Signature Algorithm: ecdsa-with-SHA256
```

</details>

### 3.3 Cadena de confianza

El servidor envió 4 certificados. Cada uno está firmado por el siguiente:

| Nivel | Sujeto | Emisor | Clave pública | Firma | Vence |
|---|---|---|---|---|---|
| 0, servidor | `example.org` | Cloudflare TLS Issuing ECC CA 3 | EC P-256 | ecdsa-with-SHA256 | dic 2026 |
| 1, intermedia | Cloudflare TLS Issuing ECC CA 3 | SSL.com TLS Transit ECC CA R2 | EC P-256 | ecdsa-with-SHA384 | may 2035 |
| 2, intermedia | SSL.com TLS Transit ECC CA R2 | SSL.com TLS ECC Root CA 2022 | EC P-384 | ecdsa-with-SHA384 | oct 2037 |
| 3, raíz | SSL.com TLS ECC Root CA 2022 | AAA Certificate Services (Comodo) | EC P-384 | sha256WithRSAEncryption | dic 2028 |

- El nivel 3 que envió el servidor está firmado por otra autoridad (Comodo), lo que parece una **certificación cruzada**: sirve para que clientes que aún no confían en la raíz nueva puedan validar por otro camino.
- El cliente termina la validación en una **raíz que ya tiene instalada** en su almacén de confianza. `openssl verify` la reconoce como ancla: es la única de la cadena que no aparece marcada como `untrusted`.
- Se ve el patrón habitual: las claves de las intermedias y la raíz son de curva elíptica, y la raíz es la que más dura (la hoja se renueva cada ~90 días).

### 3.4 Verificación de la cadena: qué significa `Verify return code: 0`

```
Verification: OK
Verify return code: 0 (ok)
```

El código 0 significa que OpenSSL pudo armar un camino válido desde el certificado del servidor hasta una raíz de confianza, y que en ese camino:
1. cada firma es válida (cada certificado está firmado por la clave pública del siguiente);
2. todos están dentro de su período de validez;
3. los certificados intermedios son de CA y tienen los usos permitidos;
4. la raíz está en el almacén de confianza local.

`openssl verify -show_chain` lo confirma y muestra el camino completo:

```
depth=0: CN=example.org (untrusted)
depth=1: ... CN=Cloudflare TLS Issuing ECC CA 3 (untrusted)
depth=2: ... CN=SSL.com TLS Transit ECC CA R2 (untrusted)
depth=3: ... CN=SSL.com TLS ECC Root CA 2022
```

Dos pruebas locales muestran qué pasa cuando algo falla:

| Prueba | Resultado | Qué enseña |
|---|---|---|
| `openssl verify` del certificado **sin** entregar las intermedias | `error 20: unable to get local issuer certificate` | Sin los intermedios no se puede armar la cadena; por eso el servidor los envía. |
| `s_client -verify_hostname otro-sitio.test` | `error 62: hostname mismatch` | Que la cadena sea válida **no alcanza**: el certificado tiene que ser para ese nombre. |

Importante: por defecto `s_client` valida la cadena pero **no el nombre del sitio**. Con `-verify_hostname example.org` sí lo valida (`Verified peername: example.org`). Un navegador siempre comprueba ambas cosas.

## 4. Resultados con Wireshark

### 4.1 Cómo se capturó

Se capturaron tres conexiones a `example.org` con `tshark` (la versión de línea de comandos de Wireshark, con el mismo motor de análisis de protocolos), por la interfaz Wi-Fi y **con un filtro de captura estricto** para guardar solo ese tráfico:

```
tshark -i <Wi-Fi> -f "host <IP de example.org> and tcp port 443" -a duration:25 -w captura.pcapng
```

Durante la captura se abrieron, con `openssl s_client` y apuntando a esa IP, tres conexiones: una por TLS 1.3, una por TLS 1.2 y otra por TLS 1.3 guardando en un archivo las claves de **esa misma sesión** (`-keylogfile`; ver 4.5). En total, 62 paquetes. La captura y el archivo de claves no se guardaron en el repositorio y se borraron al terminar, porque una captura puede contener tráfico personal y las claves de sesión permitirían descifrarlo.

Este informe no incluye capturas de pantalla de la interfaz gráfica: los datos son la salida de `tshark`. Para ver lo mismo en Wireshark, estos son los filtros de visualización:

| Qué mostrar | Filtro |
|---|---|
| Todo el handshake | `tls.handshake` |
| Client Hello / Server Hello | `tls.handshake.type == 1` / `tls.handshake.type == 2` |
| Certificado (solo se ve en TLS 1.2) | `tls.handshake.type == 11` |
| Una sola conexión | `tcp.stream eq 0` |

### 4.2 Client Hello

Es el primer mensaje, y va **en claro** en las dos versiones.

| Campo | Conexión TLS 1.3 | Conexión TLS 1.2 |
|---|---|---|
| Versión del registro | `0x0301` (TLS 1.0) | `0x0301` (TLS 1.0) |
| Versión del handshake | `0x0303` (TLS 1.2) | `0x0303` (TLS 1.2) |
| Extensión `supported_versions` | `0x0304` (**TLS 1.3**) | No está |
| SNI (`server_name`) | `example.org` | `example.org` |
| Cipher suites ofrecidas | 3 (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`) | 27 |
| Grupos soportados | `0x11ec` (X25519MLKEM768), `0x001d` (x25519), `0x0017` (secp256r1), `0x001e` (x448), `0x0018` (secp384r1), `0x0019` (secp521r1), `0x0100` y `0x0101` (ffdhe2048 y ffdhe3072) | `x25519`, `secp256r1`, `x448`, `secp384r1`, `secp521r1` |
| `key_share` | Dos claves públicas: X25519MLKEM768 (`4588`) y X25519 (`29`) | No hay |
| Tamaño del mensaje | 1469 bytes | 202 bytes |

Lo que se aprende:
- Las versiones `0x0301` y `0x0303` son campos **heredados**, que se dejan así por compatibilidad con equipos intermedios. **La versión real de TLS 1.3 está en la extensión `supported_versions`** (`0x0304`).
- El **SNI viaja en claro**: cualquiera que observe la red ve a qué sitio se conecta el cliente, aunque no vea qué hace allí.
- Las cifras de "cipher suites ofrecidas" corresponden a las conexiones **forzadas** a una versión con `s_client`: un navegador ofrece las de ambas versiones en un solo mensaje.
- El `key_share` explica los 1469 bytes: el cliente ya manda sus claves públicas en el primer mensaje (ver sección 5).

### 4.3 Server Hello

| Campo | Conexión TLS 1.3 | Conexión TLS 1.2 |
|---|---|---|
| Cipher suite elegida | `0x1302` = `TLS_AES_256_GCM_SHA384` | `0xcca9` = `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` |
| Extensión `supported_versions` | `0x0304` (TLS 1.3) | No está |
| `key_share` | Grupo `4588` (X25519MLKEM768): el servidor aceptó el híbrido post-cuántico | No hay (en TLS 1.2 la clave viaja en `ServerKeyExchange`) |

Coincide con lo que mostró OpenSSL en la sección 3.

### 4.4 Qué mensajes ve un observador de la red

Secuencia de cada conexión, **tal como la ve quien captura el tráfico**:

| TLS 1.2 | TLS 1.3 |
|---|---|
| `ClientHello` (claro) | `ClientHello` (claro) |
| `ServerHello` (claro) | `ServerHello` + `ChangeCipherSpec` (claro) |
| **`Certificate`, `ServerKeyExchange`, `ServerHelloDone` (claro)** | **Solo registros opacos: no se puede saber qué contienen** (más un `ChangeCipherSpec` de compatibilidad del cliente) |
| `ClientKeyExchange` (claro), `ChangeCipherSpec`, `Finished` (cifrado) | |
| `NewSessionTicket` (claro), `ChangeCipherSpec`, `Finished` (cifrado) | |
| Datos de aplicación (cifrados) | |

En TLS 1.2 el servidor revela su certificado completo antes de que haya cifrado alguno. En TLS 1.3, después del `ServerHello` **todo** está cifrado: el observador no ve ni el certificado ni sus extensiones.

### 4.5 Experimento: qué cambia si se tienen las claves de la sesión

En la tercera conexión se guardaron las claves de esa misma sesión y se las dio a `tshark` para descifrar. Es una conexión propia, y sin esas claves esto es imposible. Lo que apareció dentro de los registros opacos:

```
servidor -> cliente  EncryptedExtensions, Certificate, CertificateVerify, Finished
cliente  -> servidor  ChangeCipherSpec, Finished
servidor -> cliente  NewSessionTicket (x2), datos de aplicación
```

Es decir, el handshake de TLS 1.3 es el mismo que el de OpenSSL (`-msg`): lo único que impedía verlo era no tener las claves. Con ellas se ve el certificado completo (4 certificados, 3680 bytes) y el `CertificateVerify` con `ecdsa_secp256r1_sha256`. Esas claves de sesión **no viajan por la red**, y por eso un observador no las tiene.

### 4.6 Certificado y clave temporal en TLS 1.2

Como en TLS 1.2 el certificado viaja en claro, se lo puede leer en la captura. Se ven los mismos 4 certificados que en OpenSSL (3672 bytes en total), con el sujeto `example.org`, nombres alternativos `example.org` y `*.example.org`, clave pública `id-ecPublicKey` y firma `ecdsa-with-SHA256`; y la cadena de intermedias de Cloudflare y SSL.com (sección 3.3).

El mensaje `ServerKeyExchange` muestra la parte de ECDHE:

| Campo | Valor |
|---|---|
| Tipo de curva | `named_curve` |
| Curva | `x25519` |
| Largo de la clave pública temporal | 32 bytes |
| Firma | `ecdsa_secp256r1_sha256` |

Esa **firma** es importante: el servidor firma sus parámetros temporales con la clave privada del certificado, y así demuestra que la clave temporal es suya y no de un atacante en el medio. En TLS 1.3 esa función la cumple el `CertificateVerify`.

## 5. Comparación TLS 1.2 vs 1.3

Se repitió la conexión forzando cada versión (`-tls1_2` y `-tls1_3`):

| | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Cipher suite negociada | `ECDHE-ECDSA-CHACHA20-POLY1305` | `TLS_AES_256_GCM_SHA384` |
| Qué dice el nombre de la suite | Intercambio de claves (ECDHE), autenticación (ECDSA), cifrado (ChaCha20-Poly1305) | Solo cifrado y hash; el intercambio y la firma se negocian aparte |
| Intercambio de claves | ECDHE con X25519 (clave temporal de 253 bits) | X25519MLKEM768 (híbrido post-cuántico) |
| Firma del servidor | `ecdsa_secp256r1_sha256` | `ecdsa_secp256r1_sha256` |
| Mensajes del handshake | 8 (sin contar el ticket de sesión) | 7 (sin contar los 2 tickets de sesión) |
| Viajes de ida y vuelta antes de enviar datos | 2 | 1 |
| Certificado del servidor | Viaja **en claro** | Viaja **cifrado** |
| Bytes del handshake (leídos / escritos) | 4136 / 296 | 5072 / 1558 |

Mensajes observados con `-msg`:

```
TLS 1.2                                    TLS 1.3
>>> ClientHello                            >>> ClientHello (con key_share)
<<< ServerHello                            <<< ServerHello (con key_share)
<<< Certificate                            <<< EncryptedExtensions   (cifrado)
<<< ServerKeyExchange                      <<< Certificate           (cifrado)
<<< ServerHelloDone                        <<< CertificateVerify     (cifrado)
>>> ClientKeyExchange                      <<< Finished              (cifrado)
>>> ChangeCipherSpec                       >>> Finished              (cifrado)
>>> Finished                               <<< NewSessionTicket (x2)
<<< NewSessionTicket
<<< Finished
```

(En TLS 1.3, OpenSSL también muestra mensajes `ChangeCipherSpec` que se mandan solo por compatibilidad con equipos intermedios; no forman parte del handshake real.)

Qué cambia y por qué importa:
- **Menos viajes.** En TLS 1.3 el cliente manda su clave pública (`key_share`) ya en el primer mensaje, apostando al grupo que el servidor elegirá. En TLS 1.2 el intercambio de claves recién empieza cuando el servidor responde; por eso necesita un viaje más.
- **Más privacidad.** Después del ServerHello, todo el handshake de TLS 1.3 va cifrado: un observador de la red ya no ve el certificado.
- **Menos opciones inseguras.** TLS 1.3 eliminó el intercambio con RSA, las suites sin autenticación y los modos antiguos (CBC, RC4, compresión). Todas sus suites son de cifrado autenticado (AEAD).
- **El costo de la criptografía post-cuántica.** El handshake de TLS 1.3 salió *más grande* (5072 bytes leídos contra 4136), a pesar de tener menos mensajes. La causa es el `key_share` híbrido: el ClientHello mide unos 1470 bytes (su `key_share` ocupa 1258) y el ServerHello unos 1210 (su `key_share`, 1124). Una clave X25519 sola ocuparía 32 bytes. Es el precio de protegerse contra la posibilidad de que una computadora cuántica rompa algún día el intercambio clásico.
- Las cifras de bytes salen de una sola corrida de `s_client`; pueden variar un poco entre conexiones (por ejemplo por los tickets de sesión).

Qué ofreció el cliente (de `-trace` en TLS 1.3): 3 cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` y `TLS_AES_128_GCM_SHA256`), dos `key_share` (X25519MLKEM768 y X25519) y 12 algoritmos de firma aceptados. El servidor eligió la primera suite y el primer grupo.

## 6. Conexión con el kit

Los conceptos del kit aparecen en la conexión real, con diferencias que conviene entender:

| Concepto del kit | Dónde se ve en TLS | Qué hace TLS distinto |
|---|---|---|
| **SHA-256** (`hashing.py`) | El certificado está firmado con `ecdsa-with-SHA256`; el servidor firma el handshake con `ecdsa_secp256r1_sha256`; la huella del certificado es un SHA-256. | TLS usa el hash dentro de otros mecanismos (firmas, HKDF, HMAC), no solo para verificar archivos. |
| **AES-GCM** (`simetrico.py`) | La suite `TLS_AES_256_GCM_SHA384` cifra cada registro con AES-256-GCM, el mismo cifrado autenticado del kit. | La clave **no** sale de una contraseña con scrypt: sale del intercambio de claves y se deriva con HKDF. El nonce de cada registro se arma con un contador, así que nunca se repite; en el kit es aleatorio. Además, el encabezado de cada registro se autentica como datos asociados (AAD), igual que el encabezado `KCRIPTO` del kit. |
| **Firma digital** (`asimetrico.py`) | Cada certificado de la cadena es una firma de la autoridad sobre la clave pública del siguiente. El servidor firma el handshake (`CertificateVerify`) para probar que tiene su clave privada. | TLS usa ECDSA con curvas elípticas; el kit usa RSA-PSS. La idea es la misma: firma con la clave privada, verificación con la pública. |
| **Cadena de confianza** | Hoja → intermedia → intermedia → raíz del almacén local. `Verify return code: 0` significa que todas las firmas verificaron. | El kit verifica una firma contra una clave pública que *vos* elegiste. TLS necesita saber a quién confiar sin conocerlo antes, y para eso existen las raíces preinstaladas. |
| **Intercambio de claves** | ECDHE (TLS 1.2) y X25519MLKEM768 (TLS 1.3) acuerdan una clave compartida sin enviarla. | El kit no tiene intercambio de claves: asume que ya hay una contraseña compartida. En TLS las claves son **efímeras**: se generan para cada conexión y se descartan. |

Comprobación concreta: la huella SHA-256 del certificado que calcula OpenSSL (`7283112e…`) es idéntica a la que calcula `kit_cripto.hashing.sha256_archivo` sobre el mismo certificado en formato DER (1004 bytes):

```
7283112ea5a8b4e6e22a4af587c100f6086773e466e7abc0f5b3426350c14c9e
```

La diferencia más importante con el kit es el **intercambio de claves efímero**: gracias a él, aunque alguien robe más adelante la clave privada del servidor, no puede descifrar conexiones pasadas (*forward secrecy*). La clave privada del certificado solo se usa para **firmar** el handshake, nunca para proteger los datos.

## 7. Conclusiones y qué NO se puede ver

Conclusiones:
- La conexión usó TLS 1.3 con AES-256-GCM, un intercambio de claves híbrido post-cuántico y un certificado ECDSA P-256 emitido por una cadena válida de 4 niveles.
- La verificación de la cadena (`Verify return code: 0`) y la del nombre del sitio son comprobaciones distintas, y ambas hacen falta.
- TLS 1.3 es más rápido (un viaje menos), más privado (certificado cifrado) y más simple de configurar bien que TLS 1.2.

Qué **no** se puede ver desde la red, y por qué:
- **El contenido de la comunicación** (por ejemplo, la página que se descarga o los datos de un formulario). Cada registro se cifra con AES-GCM usando claves que se derivan de un secreto compartido que **nunca viaja por la red**: se calcula en cada extremo a partir de las claves efímeras. Quien captura el tráfico solo ve las partes públicas del intercambio, y de ellas no puede calcular el secreto sin resolver un problema matemático inviable con la tecnología actual (y, gracias a ML-KEM, se espera que tampoco con una computadora cuántica).
- **El certificado y las extensiones del servidor en TLS 1.3**, porque viajan cifrados con claves del handshake.
- Alterar un mensaje tampoco pasa inadvertido: la etiqueta de autenticación de GCM y el mensaje `Finished` hacen que cualquier modificación se detecte.

Qué **sí** ve un observador de la red: las direcciones IP de origen y destino, el nombre del sitio (SNI, que va en claro en el ClientHello salvo que se use Encrypted Client Hello), la versión de TLS, las suites y grupos que ofrece el cliente, las claves públicas del intercambio, y el tamaño y momento de cada paquete.
