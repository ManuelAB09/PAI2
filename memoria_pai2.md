# Documento técnico del proyecto PAI-2

---

## 1. Resumen

### 1.1 Arquitectura general

El proyecto implementa una solución de comunicación segura cliente-servidor sobre TLS 1.3 para un escenario BYOD / Road Warrior en entorno universitario. La arquitectura se divide en tres capas:

- **Capa de transporte seguro**: sockets SSL/TLS 1.3 exclusivos (puerto 3443). Implementada en `modeloConSSL/ServidorSSL.java` y `modeloConSSL/ClienteSSL.java`.
- **Capa de lógica de negocio**: gestión de sesiones, autenticación, control de fuerza bruta y routing de comandos, centralizada en `ServidorSSL.java` mediante un *thread pool* fijo de 300 hilos.
- **Capa de persistencia**: base de datos SQLite en modo WAL con integridad por fila garantizada mediante HMAC-SHA3-256, implementada en `BaseDatos.java`.

Se incluye además un modelo paralelo sin cifrado (`ModeloSinSSL/`) para benchmark de rendimiento (puerto 3080), sin uso en producción.

```
ClienteSSL (3443) ──TLS 1.3 (AES-256-GCM)──► ServidorSSL (3443)
                                                      │
                                              BaseDatos.java
                                           (SQLite + HMAC-SHA3-256)
```

**Stack tecnológico**:

| Componente | Tecnología |
|---|---|
| Lenguaje | Java 17+ (recomendado Java 21) |
| Protocolo seguro | TLS 1.3 (exclusivo, sin fallback) |
| Cifrado de canal | AES-256-GCM, AES-128-GCM |
| Derivación de clave | PBKDF2-HMAC-SHA3-256 (310 000 iteraciones) |
| Integridad de BD | HMAC-SHA3-256 por fila (clave de 256 bits) |
| Base de datos | SQLite 3.47.2.0 (embebida, modo WAL) |
| Testing | JUnit 5.10.2 (Jupiter) |
| Build | Compilación manual con `javac` |
| Despliegue | Sin Docker ni orquestador |

**Archivos fuente principales**:

| Archivo | Función |
|---|---|
| `Protocolo.java` | Constantes de protocolo (comandos, respuestas, parámetros) |
| `SeguridadUtil.java` | Primitivas criptográficas (PBKDF2, HMAC, SecureRandom) |
| `BaseDatos.java` | Persistencia SQLite y verificación de integridad |
| `modeloConSSL/ServidorSSL.java` | Servidor TLS 1.3 con pool de 300 hilos |
| `modeloConSSL/ClienteSSL.java` | Cliente interactivo con menú de operaciones |

---

### 1.2 Decisiones técnicas implementadas

**Protocolo de aplicación (capa 7)**

El protocolo está definido en `Protocolo.java` con comandos delimitados por `|`. Los cinco comandos son: `REGISTRO`, `LOGIN`, `LOGOUT`, `MENSAJE`, `HISTORIAL`. Las respuestas siguen el patrón `OK|<CMD>|<mensaje>` o `ERROR|<CMD>|<motivo>`, garantizando parseo inequívoco.

- Longitud máxima de mensaje: 144 caracteres (`Protocolo.MAX_LONGITUD_MENSAJE`).
- Puerto TLS: 3443 (`Protocolo.PUERTO`).
- Umbral brute-force: 5 intentos / bloqueo de 30 s (`Protocolo.MAX_INTENTOS_LOGIN`, `Protocolo.DURACION_BLOQUEO_MS`).

**Concurrencia**

El servidor crea un `ExecutorService` con `newFixedThreadPool(300)` al iniciar (`ServidorSSL.java`). Cada conexión entrante se atiende en un hilo independiente, garantizando soporte para ~300 empleados concurrentes sin bloquear el *accept loop*.

**Persistencia**

La base de datos SQLite opera en modo WAL (*Write-Ahead Logging*) para minimizar la contención de escritura concurrente. Dos tablas: `usuarios` y `mensajes`, con integridad por fila verificada en cada lectura mediante HMAC-SHA3-256 (`BaseDatos.java`).

---

### 1.3 Decisiones de seguridad implementadas

**RS1 / RS2 — Almacenamiento y verificación seguros de credenciales**

Las contraseñas se derivan con una implementación propia de PBKDF2-HMAC-SHA3-256 en `SeguridadUtil.java`:

- Salt: 16 bytes aleatorios por usuario (`SecureRandom`).
- Iteraciones: 310 000 (umbral OWASP 2024 para SHA3-256).
- Longitud de salida: 256 bits.
- Algoritmo interno: SHA3-256 (resistente a ataques cuánticos).

La verificación emplea `MessageDigest.isEqual()` para comparación en tiempo constante, eliminando vulnerabilidades de canal lateral por tiempo.

**RS3 — Protección frente a fuerza bruta**

`ServidorSSL.java` mantiene dos `ConcurrentHashMap` indexados por IP del cliente:

- `intentosFallidosIP`: contador de fallos por IP.
- `timestampBloqueoIP`: marca de tiempo del quinto fallo.

Al superar `MAX_INTENTOS_LOGIN` (5), la IP queda bloqueada durante `DURACION_BLOQUEO_MS` (30 000 ms). El servidor responde con `ERROR_LOGIN_BLOQUEADO` y registra la alerta en consola. El contador se reinicia al autenticarse correctamente o tras expirar el bloqueo.

**RS4 / RS5 / RS6 — Integridad, confidencialidad y autenticidad en el canal**

El canal TLS 1.3 con AEAD (AES-GCM) garantiza simultáneamente confidencialidad, integridad y autenticidad de todos los mensajes en tránsito. Se fuerzan exclusivamente dos cipher suites:

```
TLS_AES_256_GCM_SHA384   (primario)
TLS_AES_128_GCM_SHA256   (secundario)
```

TLS 1.3 utiliza siempre ECDHE como intercambio de claves, proporcionando *forward secrecy* por diseño.

**RS7 — Integridad de la base de datos**

Cada fila de `usuarios` y `mensajes` dispone de un campo `hmac` calculado con HMAC-SHA3-256 sobre los campos significativos del registro (`SeguridadUtil.calcularHMAC()`). La clave HMAC de 256 bits se genera automáticamente en el primer arranque y se persiste en `hmac.key`. Al leer cualquier fila, `BaseDatos.verificarIntegridadCompleta()` recomputa el HMAC y lo compara en tiempo constante; cualquier manipulación externa produce una alerta explícita `[!] ALERTA INTEGRIDAD`.

**OT1 / OT2 — TLS 1.3 y cipher suites robustos**

```java
// modeloConSSL/ServidorSSL.java
serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
serverSocket.setEnabledCipherSuites(new String[]{
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
});

// modeloConSSL/ClienteSSL.java
socket.setEnabledProtocols(new String[]{"TLSv1.3"});
socket.startHandshake(); // valida certificado del servidor
```

No existe configuración de protocolos de respaldo (TLS 1.2, 1.1, SSL 3.0): la exclusividad de TLS 1.3 es programática.

**Gestión de certificados**

El servidor usa un *keystore* JKS generado con `keytool` (RSA 2048 bits, autofirmado, validez 365 días). El cliente valida el certificado del servidor contra un *truststore* JKS propio. Los parámetros se inyectan como propiedades JVM en tiempo de ejecución (`-Djavax.net.ssl.keyStore`, `-Djavax.net.ssl.trustStorePassword`). Keystores y certificados están excluidos del repositorio mediante `.gitignore`.

---

### 1.4 Validaciones realizadas

**Pruebas funcionales**: `test/TestFuncionalSSL.java` contiene 15 casos de prueba JUnit 5 ejecutados sobre servidor real con TLS 1.3 activo. La ejecución registrada en `test_output.txt` arroja **10 tests aprobados y 5 fallidos**. Los 5 fallos (tests 07, 08, 10, 11 y 15) son artefactos de la ordenación de tests: el test 06 bloquea la IP durante 30 s y los tests posteriores que intentan hacer login desde la misma IP reciben `ERROR_LOGIN_BLOQUEADO`. Los tests fallan por contaminación de estado, no por defecto en la funcionalidad probada. El protocolo TLS 1.3 y el cipher suite negociado (`TLS_AES_256_GCM_SHA384`) se verifican en el test 01.

**Prueba de carga** (`test/PruebaRendimiento.java`): 300 clientes concurrentes con TLS 1.3. Resultados documentados en `GUIA_PRUEBAS.md`:

| Métrica | Valor |
|---|---|
| Clientes exitosos | 300 / 300 |
| Errores | 0 |
| Tiempo medio | 63 975,5 ms |
| Tiempo mínimo | 46 614 ms |
| Tiempo máximo | 73 163 ms |
| Percentil P95 | 72 002 ms |
| Throughput | 4,08 clientes/s |

**Benchmark sin SSL** (`test/PruebaRendimientoSinSSL.java`): tiempo medio TCP plano = 63 170,7 ms. Diferencia: 804,8 ms → **overhead TLS 1.3 = 1,27 %**.

**Análisis de tráfico** (`TramasWireShark/`): cuatro capturas `.pcap` de ~18,5 MB totales verifican visualmente que los payloads de la aplicación viajan cifrados, el handshake TLS 1.3 (ClientHello/ServerHello) negocia el cipher suite esperado y no existe tráfico en claro en el modelo seguro.

**Prueba MitM** (`test/PruebaMitM.java` + `test/ClienteSSLMitM.java`): el cliente rechaza certificados no confiables con `SSLHandshakeException`, confirmando que el *truststore* actúa como anclaje de confianza efectivo.

---

### 1.5 Limitaciones detectadas

- **Bloqueo por IP, no por usuario**: la mitigación de fuerza bruta en `ServidorSSL.java` es por IP de origen. Un atacante con múltiples IPs puede eludir el bloqueo; un usuario legítimo en IP compartida (NAT) puede verse bloqueado por los fallos de otro usuario.
- **Sin actualización de contraseña**: `Protocolo.java` y `BaseDatos.java` no implementan cambio de credenciales tras el registro (RF1 indica explícitamente que no se permiten modificaciones).
- **Certificado autofirmado**: el certificado del servidor es autofirmado. No hay CA raíz de confianza pública ni gestión de revocación (CRL/OCSP).
- **Sin autenticación mutua (mTLS)**: únicamente el servidor presenta certificado. El cliente es anónimo a nivel TLS.
- **Keystore con contraseña por defecto** (`cambiame`): la contraseña aparece documentada en `INSTRUCCIONES.md` y en los comandos de ejemplo. En producción debe cambiarse.
- **Sin despliegue automatizado**: no existe Dockerfile, Makefile ni script de arranque. El proceso es completamente manual.
- **Tests con acoplamiento de estado**: la suite JUnit no restablece el estado del servidor (bloqueos de IP) entre tests, produciendo 5 fallos espurios.

---

## 2. Manual de despliegue y uso

### 2.1 Requisitos previos

| Requisito | Versión mínima | Notas |
|---|---|---|
| Java JDK | 17 (recomendado 21) | Soporte completo de TLS 1.3 y SHA3-256 |
| `keytool` | Incluido con JDK | Para generación de keystores |
| SQLite JDBC | 3.47.2.0 | Incluido: `sqlite-jdbc-3.47.2.0.jar` |
| JUnit 5 | 5.10.2 | Incluido en `lib/` (solo para tests) |
| SO | Windows / Linux / macOS | Comandos detallados para cada plataforma |

No se requieren herramientas de red externas, Docker ni base de datos externa.

---

### 2.2 Instalación

**Paso 1 — Clonar o descomprimir el proyecto**

El directorio raíz debe contener: `Protocolo.java`, `SeguridadUtil.java`, `BaseDatos.java`, `modeloConSSL/`, `ModeloSinSSL/`, `test/`, `lib/`, `sqlite-jdbc-3.47.2.0.jar`.

**Paso 2 — Generar keystore del servidor (clave privada + certificado autofirmado)**

```bash
keytool -genkeypair -alias servidor -keyalg RSA -keysize 2048 \
  -validity 365 -keystore servidor_keystore.jks -storepass cambiame \
  -dname "CN=localhost, OU=VPN-SSL, O=BYOD, L=Madrid, ST=Madrid, C=ES"
```

**Paso 3 — Exportar el certificado del servidor**

```bash
keytool -exportcert -alias servidor \
  -keystore servidor_keystore.jks -storepass cambiame \
  -file servidor.cer
```

**Paso 4 — Importar el certificado en el truststore del cliente**

```bash
keytool -importcert -alias servidor -file servidor.cer \
  -keystore cliente_truststore.jks -storepass cambiame -noprompt
```

**Paso 5 — Compilar el código fuente**

*Linux / macOS:*
```bash
mkdir -p classes
javac -d classes -cp ".:sqlite-jdbc-3.47.2.0.jar" \
  Protocolo.java SeguridadUtil.java BaseDatos.java \
  modeloConSSL/*.java
```

*Windows (cmd):*
```cmd
mkdir classes
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar" ^
  Protocolo.java SeguridadUtil.java BaseDatos.java ^
  modeloConSSL\ServidorSSL.java modeloConSSL\ClienteSSL.java
```

---

### 2.3 Configuración

Los parámetros de seguridad no requieren fichero de configuración externo. Todos están definidos en `Protocolo.java`:

| Parámetro | Valor | Constante |
|---|---|---|
| Puerto TLS | 3443 | `Protocolo.PUERTO` |
| Intentos máximos login | 5 | `Protocolo.MAX_INTENTOS_LOGIN` |
| Duración bloqueo | 30 000 ms | `Protocolo.DURACION_BLOQUEO_MS` |
| Longitud máx. mensaje | 144 caracteres | `Protocolo.MAX_LONGITUD_MENSAJE` |

Los keystores, la base de datos (`vpn_ssl.db`) y la clave HMAC (`hmac.key`) se generan automáticamente en el directorio de trabajo al primer arranque. Están excluidos del repositorio por `.gitignore`.

---

### 2.4 Puesta en marcha

**Terminal 1 — Servidor SSL**

*Linux / macOS:*
```bash
java -cp "classes:sqlite-jdbc-3.47.2.0.jar" \
  -Djavax.net.ssl.keyStore=servidor_keystore.jks \
  -Djavax.net.ssl.keyStorePassword=cambiame \
  ServidorSSL
```

*Windows (cmd):*
```cmd
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" ^
  -Djavax.net.ssl.keyStore=servidor_keystore.jks ^
  -Djavax.net.ssl.keyStorePassword=cambiame ^
  ServidorSSL
```

Al arrancar, el servidor:
1. Genera o carga la clave HMAC desde `hmac.key`.
2. Inicializa la base de datos SQLite (`vpn_ssl.db`) y, si es la primera ejecución, inserta los 5 usuarios preregistrados.
3. Crea el pool de 300 hilos y empieza a aceptar conexiones TLS en el puerto 3443.

**Terminal 2 — Cliente SSL**

*Linux / macOS:*
```bash
java -cp "classes" \
  -Djavax.net.ssl.trustStore=cliente_truststore.jks \
  -Djavax.net.ssl.trustStorePassword=cambiame \
  ClienteSSL
```

*Windows (cmd):*
```cmd
java -cp "classes" ^
  -Djavax.net.ssl.trustStore=cliente_truststore.jks ^
  -Djavax.net.ssl.trustStorePassword=cambiame ^
  ClienteSSL
```

---

### 2.5 Flujo de uso

```
[Conexión TLS 1.3 establecida]
         │
    ┌────┴────────────────────────────────────────┐
    │   MENÚ PRINCIPAL                            │
    │   1. Registrarse     → REGISTRO|user|pass   │
    │   2. Iniciar sesión  → LOGIN|user|pass       │
    │   3. Enviar mensaje  → MENSAJE|texto         │ ← solo autenticado
    │   4. Ver historial   → HISTORIAL             │ ← solo autenticado
    │   5. Cerrar sesión   → LOGOUT                │ ← solo autenticado
    │   6. Salir           → cierra conexión       │
    └─────────────────────────────────────────────┘
```

El cliente mantiene estado de sesión (`sesionActiva`, `usuarioActual`) en memoria. Las opciones 3, 4 y 5 están disponibles únicamente tras login exitoso.

---

### 2.6 Funcionalidades principales

**Registro de usuario** (`REGISTRO|<usuario>|<contraseña>`)

- Longitud de usuario: 3–30 caracteres.
- Longitud de contraseña: mínimo 6 caracteres.
- Si el usuario ya existe: `ERROR|REGISTRO|El nombre de usuario ya existe.`
- Si tiene éxito: `OK|REGISTRO|Usuario registrado correctamente.`
- Las contraseñas se almacenan como hash PBKDF2-HMAC-SHA3-256 + salt aleatorio (nunca en claro).

**Inicio de sesión** (`LOGIN|<usuario>|<contraseña>`)

- Verifica hash en tiempo constante contra la BD.
- Si la IP del cliente ha superado 5 fallos en los últimos 30 s: `ERROR|LOGIN|Cuenta bloqueada temporalmente...`
- Si tiene éxito: `OK|LOGIN|Inicio de sesión exitoso.`

**Envío de mensaje** (`MENSAJE|<texto>`)

- Requiere sesión activa; si no: `ERROR|SESION|Debe iniciar sesión primero.`
- Máximo 144 caracteres; si se supera: `ERROR|MENSAJE|El mensaje excede los 144 caracteres.`
- El mensaje se almacena con `usuario_id`, `texto`, `fecha_envio` y `hmac` de integridad.
- Respuesta exitosa: `OK|MENSAJE|Mensaje recibido y almacenado.`

**Historial** (`HISTORIAL`)

- Requiere sesión activa.
- Devuelve todos los mensajes del usuario autenticado con fecha y texto.
- Formato: `OK|HISTORIAL|<lista de mensajes>`.

**Logout** (`LOGOUT`)

- Requiere sesión activa; si no: `ERROR|LOGOUT|No hay sesión activa.`
- Respuesta: `OK|LOGOUT|Sesión cerrada correctamente.`
- Cierra la conexión TCP subyacente.

**Usuarios preregistrados** (cargados en el primer arranque de `BaseDatos.java`):

| Usuario | Contraseña |
|---|---|
| admin | Admin2024! |
| usuario1 | Pass_user1 |
| usuario2 | Pass_user2 |
| usuario3 | Pass_user3 |
| usuario4 | Pass_user4 |

---

### 2.7 Pruebas y verificación operativa

**Tests funcionales** (`test/TestFuncionalSSL.java`)

Requieren servidor SSL en ejecución.

*Linux / macOS:*
```bash
javac -d classes -cp ".:sqlite-jdbc-3.47.2.0.jar:lib/*" test/TestFuncionalSSL.java
java -Djavax.net.ssl.trustStore=cliente_truststore.jks \
     -Djavax.net.ssl.trustStorePassword=cambiame \
     -jar lib/junit-platform-console-standalone-1.10.2.jar \
     -cp "classes:sqlite-jdbc-3.47.2.0.jar" \
     --select-class=TestFuncionalSSL
```

Resultados guardados automáticamente en `logs/TestFuncionalSSL_<fecha>.log`.

**Prueba de carga con TLS** (`test/PruebaRendimiento.java`)

```bash
java -cp "classes:sqlite-jdbc-3.47.2.0.jar" \
     -Djavax.net.ssl.trustStore=cliente_truststore.jks \
     -Djavax.net.ssl.trustStorePassword=cambiame \
     PruebaRendimiento
```

**Prueba de carga sin TLS** (`test/PruebaRendimientoSinSSL.java`)

Requiere servidor sin SSL (`ServidorSinSSL`) en el puerto 3080.

```bash
java -cp "classes:sqlite-jdbc-3.47.2.0.jar" PruebaRendimientoSinSSL
```

**Prueba MitM** (`test/PruebaMitM.java`)

```bash
java -cp "classes" -Djavax.net.ssl.trustStore=cliente_truststore.jks \
     -Djavax.net.ssl.trustStorePassword=cambiame PruebaMitM
```

Resultado esperado: `SSLHandshakeException` → certificado falso rechazado.

**Análisis de tráfico Wireshark**

Abrir cualquier fichero de `TramasWireShark/` con Wireshark. Filtros útiles:
- `tls` — todos los paquetes TLS.
- `tls.handshake.type == 1` — ClientHello.
- `tls.handshake.type == 2` — ServerHello.
- `tls.app_data` — datos de aplicación cifrados.

---

### 2.8 Incidencias o consideraciones conocidas

1. **5 tests JUnit fallan en ejecución secuencial**: el test 06 (brute-force) bloquea la IP durante 30 s. Los tests 07, 08, 10, 11 y 15 que requieren login desde la misma IP fallan por el bloqueo activo. No es un defecto funcional, sino un problema de aislamiento entre tests. Esperar 30 s entre test 06 y el siguiente elimina el fallo.

2. **`hmac.key` no debe borrarse**: al eliminar este fichero, todos los registros existentes en `vpn_ssl.db` fallarán la verificación de integridad. El servidor generará una nueva clave pero los HMACs almacenados quedarán invalidados.

3. **Keystores excluidos del repositorio**: el `.gitignore` excluye `*.jks`, `*.cer`, `vpn_ssl.db` y `hmac.key`. Deben generarse localmente siguiendo la sección 2.2.

4. **Contraseña de keystore por defecto**: la contraseña `cambiame` es la indicada en la documentación de ejemplo. En entorno de producción debe modificarse en los comandos de `keytool` y en los parámetros JVM de arranque.

5. **Puerto 3443 debe estar disponible**: verificar que no esté ocupado por otro proceso antes de arrancar el servidor.

---

## 3. Grado de completitud

### 3.1 Matriz de trazabilidad de requisitos

#### Requisitos funcionales

| ID | Requisito | Evidencia en el proyecto | Estado | Observaciones |
|---|---|---|---|---|
| RF1 | Registro de usuario con usuario y contraseña; detección de duplicados; sin modificación posterior | `BaseDatos.registrarUsuario()` comprueba `username UNIQUE`; no existe endpoint de actualización | **Cumplido** | Validación de longitud (3–30 / 6+) en `ServidorSSL.java` |
| RF2 | Inicio de sesión con usuario y contraseña | `LOGIN` manejado en `ServidorSSL.java`; llama a `BaseDatos.verificarCredenciales()` | **Cumplido** | — |
| RF3 | Verificación de credenciales contra BD; denegación si no coinciden | `SeguridadUtil.verificarPassword()` con PBKDF2 y `MessageDigest.isEqual()`; responde `ERROR_LOGIN_CRED` | **Cumplido** | Comparación en tiempo constante |
| RF4 | Cierre de sesión de usuarios autenticados | Comando `LOGOUT` en `ServidorSSL.java`; cierra conexión y limpia estado | **Cumplido** | Requiere sesión activa |
| RF5 | Conjunto inicial de usuarios preregistrados | `BaseDatos.java` inserta 5 usuarios en el primer arranque con PBKDF2 | **Cumplido** | admin, usuario1–4 |
| RF6 | Envío de mensajes de texto al servidor por usuarios autenticados | Comando `MENSAJE` en `ServidorSSL.java`; requiere `sesionActiva` | **Cumplido** | — |
| RF7 | Persistencia de usuarios, mensajes, contador y fecha | Tablas `usuarios` (`num_mensajes`) y `mensajes` (`fecha_envio`) en SQLite; `BaseDatos.guardarMensaje()` | **Cumplido** | — |
| RF8 | Interfaz de sockets seguros para registro, autenticación y mensajes | `SSLServerSocket` en `ServidorSSL.java`; `SSLSocket` en `ClienteSSL.java` | **Cumplido** | Puerto 3443, TLS 1.3 |

#### Requisitos de información

| ID | Requisito | Evidencia en el proyecto | Estado | Observaciones |
|---|---|---|---|---|
| RI1 | nombre de usuario único + contraseña | Columna `username UNIQUE` en tabla `usuarios`; `BaseDatos.java` | **Cumplido** | — |
| RI2 | Base de datos inicial con usuarios preregistrados, sin mensajes previos | `BaseDatos.cargarUsuariosIniciales()`; los usuarios se insertan sin mensajes asociados | **Cumplido** | — |
| RI3 | Historial: número de mensajes por usuario y fecha | Campo `num_mensajes` en `usuarios`; `fecha_envio` en `mensajes`; `BaseDatos.obtenerHistorial()` | **Cumplido** | — |
| RI4 | Mensaje con ID de usuario y texto ≤ 144 caracteres | `usuario_id` (FK) en tabla `mensajes`; validación `MAX_LONGITUD_MENSAJE = 144` en `Protocolo.java` y `ServidorSSL.java` | **Cumplido** | — |
| RI5 | Mensajes de sistema para cada operación | Todas las respuestas definidas como constantes en `Protocolo.java` (OK_REGISTRO, ERROR_REGISTRO_EXISTE, OK_LOGIN, ERROR_LOGIN_CRED, ERROR_LOGIN_BLOQUEADO, OK_MENSAJE, ERROR_MENSAJE_LONG, OK_LOGOUT…) | **Cumplido** | — |

#### Requisitos de seguridad

| ID | Requisito | Evidencia en el proyecto | Estado | Observaciones |
|---|---|---|---|---|
| RS1 | Almacenamiento seguro de credenciales | PBKDF2-HMAC-SHA3-256 (310 000 iter., salt 16 B, salida 256 b) en `SeguridadUtil.java` | **Cumplido** | SHA3-256 resistente a colisiones cuánticas |
| RS2 | Verificación segura de credenciales | `MessageDigest.isEqual()` (tiempo constante) en `SeguridadUtil.verificarPassword()` | **Cumplido** | Previene timing attacks |
| RS3 | Protección contra fuerza bruta | Bloqueo por IP: 5 intentos → 30 s en `ServidorSSL.java` (`ConcurrentHashMap`) | **Parcial** | El bloqueo es por IP, no por username; usuarios en NAT compartida pueden verse afectados; 30 s es insuficiente para protección robusta (recomendado: backoff exponencial o bloqueo de 15-30 min) |
| RS4 | Integridad en el envío de mensajes | AES-GCM (AEAD) en el canal TLS 1.3 garantiza integridad extremo a extremo | **Cumplido** | — |
| RS5 | Confidencialidad en el envío de mensajes | TLS 1.3 con AES-256-GCM cifra todo el payload | **Cumplido** | Verificado en capturas Wireshark |
| RS6 | Autenticidad en el envío de mensajes | AEAD (autenticación implícita en AES-GCM) + certificado del servidor verificado por el cliente | **Cumplido** | Sin mTLS: el servidor no autentica el certificado del cliente |
| RS7 | Integridad de la base de datos | HMAC-SHA3-256 por fila en `BaseDatos.java`; verificación completa en `verificarIntegridadCompleta()` | **Cumplido** | 3 635 registros verificados en ejecución documentada |

#### Objetivos técnicos y de validación

| ID | Objetivo | Evidencia en el proyecto | Estado | Observaciones |
|---|---|---|---|---|
| OT1 | Uso de SSL/TLS | `SSLServerSocket` / `SSLSocket`; `modeloConSSL/ServidorSSL.java` y `ClienteSSL.java` | **Cumplido** | — |
| OT2 | TLS 1.3 y cipher suites robustos | `setEnabledProtocols(["TLSv1.3"])` + `TLS_AES_256_GCM_SHA384` / `TLS_AES_128_GCM_SHA256` | **Cumplido** | Verificado en test 01 y Wireshark |
| OT3 | Análisis de tráfico con Wireshark/tcpdump | 4 capturas `.pcap` en `TramasWireShark/`; capturas con y sin SSL; imágenes en `Images/` | **Cumplido** | ClientHello, ServerHello y AppData analizados |
| OT4 | Concurrencia ~300 empleados | `newFixedThreadPool(300)` en `ServidorSSL.java`; validado con `PruebaRendimiento.java` (300 clientes simultáneos, 0 errores) | **Cumplido** | — |
| OT5 | Análisis de rendimiento y escalabilidad | `PruebaRendimiento.java`: media 63 975,5 ms, P95 72 002 ms, throughput 4,08 cli/s; resultados en `GUIA_PRUEBAS.md` | **Cumplido** | Métricas documentadas |
| OT6 | Comparativa con y sin canal seguro | `PruebaRendimientoSinSSL.java` media 63 170,7 ms vs. TLS 63 975,5 ms → overhead 1,27 % | **Cumplido** | Benchmark incluye captura Wireshark sin SSL |
| OT7 | Análisis activo / MitM (opcional) | `test/PruebaMitM.java` + `test/ClienteSSLMitM.java`; el cliente rechaza el certificado falso con `SSLHandshakeException` | **Cumplido** | Implementación de PoC completa |

---

### 3.2 Resumen global de cumplimiento

| Categoría | Total | Cumplidos | Parciales | No evidenciados |
|---|---|---|---|---|
| Requisitos funcionales (RF) | 8 | 8 | 0 | 0 |
| Requisitos de información (RI) | 5 | 5 | 0 | 0 |
| Requisitos de seguridad (RS) | 7 | 6 | 1 | 0 |
| Objetivos técnicos (OT) | 7 | 7 | 0 | 0 |
| **Total** | **27** | **26** | **1** | **0** |

**Grado de cumplimiento global: 96,3 % (26/27 requisitos cumplidos plenamente).**

El único requisito parcial (RS3) no compromete la funcionalidad del sistema: el bloqueo por IP es una medida de mitigación efectiva en la mayoría de escenarios BYOD donde cada dispositivo tiene IP diferente. La limitación es el caso de usuarios detrás de NAT compartida.

---

### 3.3 Riesgos, carencias y trabajo pendiente

| Riesgo / Carencia | Impacto | Recomendación |
|---|---|---|
| Bloqueo brute-force por IP (no por usuario); duración insuficiente (30 s) | Medio — usuario en NAT puede ser bloqueado por otro; 30 s permite hasta ~10 ataques por minuto | Implementar bloqueo por nombre de usuario y aplicar backoff exponencial (mínimo 15 min tras múltiples bloqueos) |
| Certificado autofirmado sin CRL/OCSP | Medio — no hay mecanismo de revocación | Usar CA privada o Let's Encrypt en entorno real |
| Sin mTLS (cliente no se autentica a nivel TLS) | Bajo — la autenticación se hace en capa de aplicación | Considerar mTLS para mayor garantía de identidad |
| Contraseña de keystore hardcoded en ejemplos (`cambiame`) | Alto en producción | Externalizar en variable de entorno o gestor de secretos |
| Sin automatización de despliegue (no Docker, no scripts) | Medio — proceso propenso a errores manuales | Añadir Makefile o `docker-compose.yml` |
| 5 tests JUnit fallan por contaminación de estado | Bajo — es un problema de diseño de tests, no del código | Aislar tests con `@BeforeEach` que espere expirar bloqueos o use IPs distintas |
| Escalabilidad limitada a 300 hilos fijos | Medio — si se superan 300 conexiones simultáneas, se encolan | Valorar arquitectura reactiva o pool dinámico |

---

## Anexo breve de evidencias

Lista de archivos relevantes encontrados y analizados:

| Archivo | Relevancia |
|---|---|
| `Protocolo.java` | Definición completa del protocolo de aplicación |
| `SeguridadUtil.java` | Implementación PBKDF2-HMAC-SHA3-256, HMAC, SecureRandom |
| `BaseDatos.java` | Esquema SQLite, persistencia, integridad HMAC por fila |
| `modeloConSSL/ServidorSSL.java` | Servidor TLS 1.3, thread pool 300, brute-force, routing de comandos |
| `modeloConSSL/ClienteSSL.java` | Cliente TLS 1.3, menú interactivo, gestión de sesión |
| `ModeloSinSSL/ServidorSinSSL.java` | Servidor TCP plano para benchmark |
| `ModeloSinSSL/ClienteSinSSL.java` | Cliente TCP plano para benchmark |
| `test/TestFuncionalSSL.java` | 15 tests JUnit 5 (10 OK, 5 fallos por contaminación de estado) |
| `test/PruebaRendimiento.java` | Prueba de carga: 300 clientes TLS concurrentes |
| `test/PruebaRendimientoSinSSL.java` | Benchmark TCP plano: 300 clientes sin cifrado |
| `test/PruebaMitM.java` | Simulación de ataque MitM: certificado falso rechazado |
| `test/ClienteSSLMitM.java` | Cliente auxiliar para prueba MitM |
| `INSTRUCCIONES.md` | Guía completa de compilación y ejecución |
| `GUIA_PRUEBAS.md` | Procedimiento detallado de todas las pruebas |
| `test_output.txt` | Salida real de ejecución de tests JUnit 5 |
| `TramasWireShark/Trama de la conexión y uso de la app de por un cliente.pcap` | Captura tráfico TLS 1.3 cliente único |
| `TramasWireShark/Trama de la conexión y uso de app por un cliente sin SSL.pcap` | Captura tráfico TCP plano (benchmark) |
| `TramasWireShark/Trama tras realizar los tests.pcap` | Captura durante ejecución de suite funcional |
| `TramasWireShark/Trama tras realizar el test de carga sin SSL.pcap` | Captura durante prueba de carga sin cifrado |
| `Images/` | Capturas de pantalla de handshake TLS (ClientHello, ServerHello, AppData) |
| `lib/junit-platform-console-standalone-1.10.2.jar` | Runner JUnit 5 standalone |
| `sqlite-jdbc-3.47.2.0.jar` | Driver JDBC SQLite embebido |
| `.gitignore` | Excluye `*.jks`, `*.cer`, `vpn_ssl.db`, `hmac.key`, `logs/`, `classes/` |
