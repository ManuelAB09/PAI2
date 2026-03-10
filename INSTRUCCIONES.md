# VPN SSL BYOD — Instrucciones de Compilación y Ejecución

## Estructura del Proyecto

```
PAI2/
├── Protocolo.java              # Constantes compartidas
├── SeguridadUtil.java          # Utilidades de seguridad (PBKDF2, HMAC)
├── BaseDatos.java              # Persistencia SQLite + integridad HMAC
├── modeloConSSL/               # Modelo con TLS 1.3
│   ├── ServidorSSL.java
│   └── ClienteSSL.java
├── ModeloSinSSL/               # Modelo sin cifrado (benchmark)
│   ├── ServidorSinSSL.java
│   └── ClienteSinSSL.java
├── test/                       # Tests y pruebas
│   ├── TestFuncionalSSL.java
│   ├── PruebaRendimiento.java
│   ├── PruebaRendimientoSinSSL.java
│   ├── PruebaMitM.java
│   └── ClienteSSLMitM.java
├── lib/                        # JUnit 5 standalone
├── logs/                       # Logs autogenerados por las pruebas
└── sqlite-jdbc-3.47.2.0.jar
```

## Requisitos Previos

- **Java 17+** (recomendado Java 21 para soporte completo de TLS 1.3 y SHA3-256)
- Driver JDBC de SQLite: `sqlite-jdbc-3.47.2.0.jar` (incluido en el proyecto)

---

## 1. Generación del Keystore y Truststore

### Paso 1: Generar el Keystore del Servidor (clave privada + certificado autofirmado)

```bash
keytool -genkeypair -alias servidor -keyalg RSA -keysize 2048 -validity 365 -keystore servidor_keystore.jks -storepass cambiame -dname "CN=localhost, OU=VPN-SSL, O=BYOD, L=Madrid, ST=Madrid, C=ES"
```

### Paso 2: Exportar el certificado del servidor

```bash
keytool -exportcert -alias servidor -keystore servidor_keystore.jks -storepass cambiame -file servidor.cer
```

### Paso 3: Importar el certificado en el Truststore del Cliente

```bash
keytool -importcert -alias servidor -file servidor.cer -keystore cliente_truststore.jks -storepass cambiame -noprompt
```

### Verificar (opcional)

```bash
keytool -list -keystore servidor_keystore.jks -storepass cambiame
keytool -list -keystore cliente_truststore.jks -storepass cambiame
```

> **Nota**: Se generarán los ficheros `servidor_keystore.jks`, `servidor.cer` y `cliente_truststore.jks` en el directorio actual.

---

## 2. Compilación

Compilar todos los ficheros Java incluyendo el driver SQLite en el classpath. Los archivos `.class` se generan en la carpeta `classes/`:

### 2.1 Modelo con SSL (TLS 1.3)

**Windows (cmd):**

```cmd
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar" Protocolo.java SeguridadUtil.java BaseDatos.java modeloConSSL\ServidorSSL.java modeloConSSL\ClienteSSL.java
```

**Windows (PowerShell):**

```powershell
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar" Protocolo.java SeguridadUtil.java BaseDatos.java modeloConSSL\ServidorSSL.java modeloConSSL\ClienteSSL.java
```

**Linux / macOS:**

```bash
javac -d classes -cp ".:sqlite-jdbc-3.47.2.0.jar" Protocolo.java SeguridadUtil.java BaseDatos.java modeloConSSL/*.java
```

### 2.2 Modelo sin SSL (benchmark, sin cifrado)

**Windows (cmd / PowerShell):**

```cmd
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar" Protocolo.java SeguridadUtil.java BaseDatos.java ModeloSinSSL\ServidorSinSSL.java ModeloSinSSL\ClienteSinSSL.java
```

**Linux / macOS:**

```bash
javac -d classes -cp ".:sqlite-jdbc-3.47.2.0.jar" Protocolo.java SeguridadUtil.java BaseDatos.java ModeloSinSSL/*.java
```

### 2.3 Tests (todos en `test/`)

```cmd
javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar;lib/*" test\TestFuncionalSSL.java test\PruebaRendimiento.java test\PruebaRendimientoSinSSL.java test\PruebaMitM.java test\ClienteSSLMitM.java
```

---

## 3. Ejecución del Servidor SSL

Abrir una terminal y ejecutar:

### Windows (cmd)

```cmd
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" -Djavax.net.ssl.keyStore=servidor_keystore.jks -Djavax.net.ssl.keyStorePassword=cambiame ServidorSSL
```

### Windows (PowerShell)

```powershell
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" "-Djavax.net.ssl.keyStore=servidor_keystore.jks" "-Djavax.net.ssl.keyStorePassword=cambiame" ServidorSSL
```

### Linux / macOS

```bash
java -cp "classes:sqlite-jdbc-3.47.2.0.jar" -Djavax.net.ssl.keyStore=servidor_keystore.jks -Djavax.net.ssl.keyStorePassword=cambiame ServidorSSL
```

---

## 4. Ejecución del Cliente SSL

Abrir **otra** terminal y ejecutar:

### Windows (cmd)

```cmd
java -cp "classes" -Djavax.net.ssl.trustStore=cliente_truststore.jks -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSL
```

### Windows (PowerShell)

```powershell
java -cp "classes" "-Djavax.net.ssl.trustStore=cliente_truststore.jks" "-Djavax.net.ssl.trustStorePassword=cambiame" ClienteSSL
```

### Linux / macOS

```bash
java -cp "classes" -Djavax.net.ssl.trustStore=cliente_truststore.jks -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSL
```

---

## 4b. Ejecución del Modelo Sin SSL (benchmark)

Este modelo usa sockets TCP planos (sin cifrado). No requiere keystore ni truststore.

### Servidor Sin SSL

```cmd
java -cp "classes;sqlite-jdbc-3.47.2.0.jar" ServidorSinSSL
```

> El servidor sin SSL escucha en el **puerto 3080** (diferente al 3443 del SSL).

### Cliente Sin SSL

```cmd
java -cp "classes" ClienteSinSSL
```

---

## 5. Usuarios Pre-registrados

El sistema carga automáticamente los siguientes usuarios al primer arranque:

| Usuario    | Contraseña   |
|------------|--------------|
| admin      | Admin2024!   |
| usuario1   | Pass_user1   |
| usuario2   | Pass_user2   |
| usuario3   | Pass_user3   |
| usuario4   | Pass_user4   |

---

## 6. Ficheros Generados en Ejecución

| Fichero          | Descripción                                    |
|------------------|------------------------------------------------|
| `vpn_ssl.db`     | Base de datos SQLite con usuarios y mensajes   |
| `hmac.key`       | Clave HMAC para verificación de integridad     |
| `logs/`          | Directorio con logs autogenerados por las pruebas |

> **¡Importante!** No modifique ni elimine `hmac.key` salvo que desee regenerar la integridad de toda la base de datos. Si la clave cambia, los registros existentes no pasarán la verificación de integridad.

---

## 7. Archivos por Carpeta

| Carpeta | Ficheros | Descripción |
|---------|----------|-------------|
| `modeloConSSL/` | `ServidorSSL.java`, `ClienteSSL.java` | Servidor y cliente con TLS 1.3 |
| `ModeloSinSSL/` | `ServidorSinSSL.java`, `ClienteSinSSL.java` | Servidor y cliente sin cifrado (benchmark) |
| `test/` | `TestFuncionalSSL.java`, `PruebaRendimiento.java`, `PruebaRendimientoSinSSL.java`, `PruebaMitM.java`, `ClienteSSLMitM.java` | Todos los tests y pruebas |
| (raíz) | `Protocolo.java`, `SeguridadUtil.java`, `BaseDatos.java` | Código compartido por ambos modelos |
