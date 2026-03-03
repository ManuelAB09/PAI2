# Guía Completa de Pruebas — VPN SSL BYOD

Instrucciones paso a paso para ejecutar todas las pruebas: funcionales (JUnit 5), rendimiento (300 clientes), análisis criptográfico (Wireshark) y ataque MitM (Python PoC).

---

## 1. Pruebas Funcionales (JUnit 5)

### Compilar

```cmd
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar;lib/*" test\TestFuncionalSSL.java
```

### Ejecutar (requiere servidor activo)

**cmd:**

```cmd
java -Djavax.net.ssl.trustStore=cliente_truststore.jks -Djavax.net.ssl.trustStorePassword=cambiame -jar lib\junit-platform-console-standalone-1.10.2.jar -cp "classes;sqlite-jdbc-3.47.2.0.jar" --select-class=TestFuncionalSSL
```

**PowerShell** (flags `-D` entrecomillados):

```powershell
java "-Djavax.net.ssl.trustStore=cliente_truststore.jks" "-Djavax.net.ssl.trustStorePassword=cambiame" -jar lib\junit-platform-console-standalone-1.10.2.jar -cp "classes;sqlite-jdbc-3.47.2.0.jar" --select-class=TestFuncionalSSL
```

### Tests incluidos

| # | Test | Valida |
|---|---|---|
| 01 | `testConexionTLS13` | Protocolo TLSv1.3 + cipher suite AES-GCM |
| 02 | `testRegistroExitoso` | Registro de nuevo usuario → OK |
| 03 | `testRegistroDuplicado` | Registro duplicado → ERROR |
| 04 | `testLoginExitoso` | Login correcto → OK |
| 05 | `testLoginIncorrecto` | Login con contraseña errónea → ERROR |
| 06 | `testBruteForceBloqueo` | 5 fallos → 6º devuelve BLOQUEADO |
| 07 | `testMensajeExitoso` | Mensaje ≤144 chars → OK |
| 08 | `testMensajeLargo` | Mensaje >144 chars → ERROR |
| 09 | `testMensajeSinLogin` | Mensaje sin autenticar → ERROR |
| 10 | `testHistorial` | Historial contiene mensajes enviados |
| 11 | `testLogout` | Cerrar sesión → OK |
| 12 | `testLogoutSinSesion` | Logout sin sesión → ERROR |
| 13 | `testComandoInvalido` | Comando inexistente → ERROR |
| 14 | `testIntegridadBD` | HMAC de todas las filas verificado |
| 15 | `testUsuariosPreregistrados` | Login admin/Admin2024! → OK |

---

## 2. Prueba de Rendimiento (300 Clientes)

### Compilar

```cmd
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar" PruebaRendimiento.java
```

### Ejecutar (requiere servidor activo)

**cmd:**

```cmd
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" -Djavax.net.ssl.trustStore=cliente_truststore.jks -Djavax.net.ssl.trustStorePassword=cambiame PruebaRendimiento
```

**PowerShell:**

```powershell
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" "-Djavax.net.ssl.trustStore=cliente_truststore.jks" "-Djavax.net.ssl.trustStorePassword=cambiame" PruebaRendimiento
```

### Métricas reportadas

- **Clientes exitosos / errores**: ¿el servidor colapsa?
- **Tiempo medio, mínimo, máximo**: latencia por cliente
- **P95**: percentil 95 — el 95% de clientes completó en X ms
- **Throughput**: clientes completados por segundo

### Metodología SSL vs Texto Plano

Para documentar la "pérdida de rendimiento" por usar TLS:

1. **Paso A** — Ejecutar `PruebaRendimiento.java` contra el servidor SSL → anotar **Media TLS**
2. **Paso B** — Crear un `ServidorTextoPlano.java` idéntico pero usando `ServerSocket` en lugar de `SSLServerSocket` (misma lógica, sin cifrado)
3. **Paso C** — Crear `PruebaRendimientoPlano.java` que use `Socket` en lugar de `SSLSocket`
4. **Paso D** — Ejecutar y anotar **Media TCP**
5. **Cálculo**: `Overhead TLS = ((Media_TLS - Media_TCP) / Media_TCP) × 100%`

> **Nota**: El overhead típico de TLS 1.3 es de 1-3 ms adicionales por handshake, gracias al 0-RTT/1-RTT de TLS 1.3. Esto supone un overhead de aproximadamente 10-30% respecto a texto plano para conexiones cortas.

---

## 3. Análisis Criptográfico con Wireshark

### 3.1 Captura de tráfico en localhost

#### Opción A: Npcap + Wireshark (recomendado en Windows)

1. **Instalar Npcap** desde <https://npcap.com> con la opción "**Support loopback traffic**" marcada.
2. **Abrir Wireshark**, seleccionar la interfaz **"Npcap Loopback Adapter"** o **"Adapter for loopback traffic capture"**.
3. Iniciar captura y ejecutar servidor + cliente.

#### Opción B: RawCap (alternativa ligera)

1. Descargar **RawCap** desde <https://www.netresec.com/?page=RawCap>
2. Ejecutar como administrador:

   ```cmd
   RawCap.exe 127.0.0.1 captura_ssl.pcap
   ```

3. Ejecutar servidor + cliente mientras RawCap captura.
4. Detener con Ctrl+C y abrir `captura_ssl.pcap` en Wireshark.

### 3.2 Filtros de Wireshark

Aplicar estos filtros en la barra de filtro de Wireshark:

| Filtro | Propósito |
|---|---|
| `tcp.port == 3443` | Ver todo el tráfico del servidor |
| `tls` | Solo paquetes TLS |
| `tls.handshake` | Solo paquetes de handshake TLS |
| `tls.handshake.type == 1` | ClientHello |
| `tls.handshake.type == 2` | ServerHello |
| `tls.record.content_type == 23` | Application Data (datos cifrados) |
| `tls.handshake.extensions.supported_versions == 0x0304` | Negociación TLS 1.3 |

### 3.3 Qué buscar — Evidencias para el informe

#### A) Negociación TLS 1.3 correcta

1. Filtrar por `tls.handshake.type == 1` → Expandir **ClientHello**:
   - **Supported Versions Extension**: debe mostrar `TLS 1.3 (0x0304)`
   - **Cipher Suites**: debe incluir `TLS_AES_256_GCM_SHA384` y/o `TLS_AES_128_GCM_SHA256`

2. Filtrar por `tls.handshake.type == 2` → Expandir **ServerHello**:
   - **Supported Version**: `TLS 1.3 (0x0304)`
   - **Cipher Suite**: `TLS_AES_256_GCM_SHA384 (0x1302)` o `TLS_AES_128_GCM_SHA256 (0x1301)`

> **Captura de pantalla**: Hacer captura del ServerHello mostrando TLS 1.3 y el cipher suite.

#### B) Confidencialidad — Datos cifrados

1. Filtrar: `tls.record.content_type == 23 && tcp.port == 3443`
2. Seleccionar un paquete **Application Data**.
3. En el panel inferior (hexdump), verificar que los datos son **ininteligibles** (cifrados).
4. **NO** debe aparecer texto plano como "LOGIN", "REGISTRO", "MENSAJE", contraseñas ni nombres de usuario.

> **Captura de pantalla**: Mostrar el contenido hexadecimal del Application Data cifrado.

#### C) Integridad — AES-GCM

TLS 1.3 con AES-GCM proporciona **AEAD** (Authenticated Encryption with Associated Data):

- Los datos se cifran Y se autentican con un MAC integrado.
- Cualquier modificación en tránsito sería detectada y la conexión se cerraría.
- **Evidencia**: Mostrar que el cipher suite negociado es `TLS_AES_256_GCM_SHA384`, que es un algoritmo AEAD.

#### D) Resumen de evidencias

| Propiedad | Cómo demostrarlo | Filtro Wireshark |
|---|---|---|
| **TLS 1.3** | ServerHello → version 0x0304 | `tls.handshake.type == 2` |
| **Cipher Suite robusto** | ServerHello → AES-256-GCM | `tls.handshake.type == 2` |
| **Confidencialidad** | Application Data sin texto plano | `tls.record.content_type == 23` |
| **Integridad** | AEAD (GCM incluye autenticación) | Cipher suite info |

---

## 4. Ataque Man-in-the-Middle (MitM)

### 4.1 Resumen

El ataque demuestra que un atacante que intercepta la comunicación entre cliente y servidor **NO puede** descifrar el tráfico porque:

- El cliente Java verifica el certificado del servidor contra su **TrustStore**.
- Un certificado falso genera `SSLHandshakeException` y la conexión se **rechaza**.

### 4.2 Ejecución del ataque

#### Paso 1: Arrancar el servidor real

**cmd:**

```cmd
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" -Djavax.net.ssl.keyStore=servidor_keystore.jks -Djavax.net.ssl.keyStorePassword=cambiame ServidorSSL
```

**PowerShell:**

```powershell
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" "-Djavax.net.ssl.keyStore=servidor_keystore.jks" "-Djavax.net.ssl.keyStorePassword=cambiame" ServidorSSL
```

#### Paso 2: Compilar y arrancar el proxy MitM (terminal 2)

```cmd
javac -d classes PruebaMitM.java ClienteSSLMitM.java
java -cp classes PruebaMitM
```

Esto:

- Genera un keystore con un certificado autofirmado **falso** via keytool.
- Levanta un proxy TLS en el **puerto 4443**.

#### Paso 3: Ejecutar el cliente MitM (terminal 3)

**cmd:**

```cmd
java -cp classes -Djavax.net.ssl.trustStore=cliente_truststore.jks -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSLMitM
```

**PowerShell:**

```powershell
java -cp classes "-Djavax.net.ssl.trustStore=cliente_truststore.jks" "-Djavax.net.ssl.trustStorePassword=cambiame" ClienteSSLMitM
```

#### Resultado esperado

**En el cliente (terminal 3):**

```
✅ SSLHandshakeException capturada correctamente.
✅ El cliente RECHAZÓ el certificado falso del atacante.
✅ El TrustStore protege contra el ataque MitM.
```

**En el proxy MitM (terminal 2):**

```
[MitM] ✅ Handshake FALLIDO (esperado): [SSL: CERTIFICATE_REQUIRED]
[MitM] ✅ El cliente Java RECHAZÓ el certificado falso.
```

### 4.3 ¿Por qué funciona la protección?

```
┌─────────┐         ┌──────────────┐         ┌──────────────┐
│ Cliente  │ ──TLS──►│ Proxy MitM   │ ──TLS──►│ Servidor     │
│ Java     │         │ (cert falso) │         │ (cert real)  │
└─────────┘         └──────────────┘         └──────────────┘
     │                      │
     │  SSLHandshakeException!
     │  El truststore NO contiene
     │  el cert del proxy atacante.
     │  CONEXIÓN RECHAZADA ✅
```

1. El cliente Java solo confía en los certificados de `cliente_truststore.jks`.
2. El proxy presenta un certificado firmado por una CA diferente (autofirmado por el atacante).
3. Java detecta que el certificado no es de confianza → lanza `SSLHandshakeException`.
4. **Resultado**: la comunicación NUNCA se establece con el atacante.

### 4.4 Contraejemplo: ¿qué pasaría sin TrustStore?

Si el cliente aceptara cualquier certificado (configuración insegura con `TrustAllCerts`):

- El proxy MitM podría interceptar, leer y modificar todo el tráfico.
- Las credenciales de login serían visibles para el atacante.
- **Moraleja**: Nunca desactivar la verificación de certificados en producción.
