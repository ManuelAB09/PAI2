import org.junit.jupiter.api.*;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import javax.net.ssl.*;

/**
 * TestFuncionalSSL.java
 * 
 * Suite de pruebas funcionales JUnit 5 para la VPN SSL BYOD.
 * Se conecta al servidor SSL real para validar todos los requisitos funcionales
 * y de seguridad.
 * 
 * PRE-REQUISITO: El servidor ServidorSSL debe estar en ejecución antes de
 * lanzar estos tests.
 * 
 * Compilación:
 * javac -d classes -cp ".;sqlite-jdbc-3.47.2.0.jar;lib/*" test/TestFuncionalSSL.java
 * 
 * Ejecución:
 * java -Djavax.net.ssl.trustStore=cliente_truststore.jks
 * -Djavax.net.ssl.trustStorePassword=cambiame
 * -jar lib/junit-platform-console-standalone-1.10.2.jar
 * -cp "classes;sqlite-jdbc-3.47.2.0.jar"
 * --select-class=TestFuncionalSSL
 * 
 * @author Manuel
 */
@TestMethodOrder(OrderAnnotation.class)
@DisplayName("VPN SSL BYOD - Tests Funcionales")
public class TestFuncionalSSL {

    // ======================== CONFIGURACIÓN ========================

    private static final String HOST = "localhost";
    private static final int PUERTO = 3443;
    private static final String[] PROTOCOLOS = { "TLSv1.3" };
    private static final String[] CIPHER_SUITES = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256"
    };

    /** Usuario de prueba único para evitar conflictos entre ejecuciones */
    private static final String TEST_USER = "testqa_" + System.currentTimeMillis();
    private static final String TEST_PASS = "TestPass123!";

    // ======================== UTILIDADES ========================

    /**
     * Abre una conexión SSL al servidor y devuelve socket+streams.
     * El llamante es responsable de cerrar los recursos.
     */
    private ConexionSSL conectar() throws Exception {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) factory.createSocket(HOST, PUERTO);
        socket.setEnabledProtocols(PROTOCOLOS);
        socket.setEnabledCipherSuites(CIPHER_SUITES);
        socket.startHandshake();

        BufferedReader entrada = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), "UTF-8"));
        PrintWriter salida = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

        return new ConexionSSL(socket, entrada, salida);
    }

    /**
     * Envía un comando y lee la respuesta.
     */
    private String enviarComando(ConexionSSL conn, String comando) throws IOException {
        conn.salida.println(comando);
        return conn.entrada.readLine();
    }

    /**
     * Clase interna para agrupar los recursos de una conexión SSL.
     */
    private static class ConexionSSL implements AutoCloseable {
        final SSLSocket socket;
        final BufferedReader entrada;
        final PrintWriter salida;

        ConexionSSL(SSLSocket socket, BufferedReader entrada, PrintWriter salida) {
            this.socket = socket;
            this.entrada = entrada;
            this.salida = salida;
        }

        @Override
        public void close() throws Exception {
            salida.close();
            entrada.close();
            socket.close();
        }
    }

    // ======================== TEST 1: CONEXIÓN TLS 1.3 ========================

    @Test
    @Order(1)
    @DisplayName("01 - Conexión TLS 1.3 exitosa con cipher suite robusto")
    void testConexionTLS13() throws Exception {
        try (ConexionSSL conn = conectar()) {
            SSLSession session = conn.socket.getSession();
            // Verificar que el protocolo negociado es TLS 1.3
            assertEquals("TLSv1.3", session.getProtocol(),
                    "El protocolo negociado debe ser TLSv1.3");

            // Verificar que el cipher suite es uno de los permitidos
            String cipher = session.getCipherSuite();
            assertTrue(
                    cipher.equals("TLS_AES_256_GCM_SHA384") || cipher.equals("TLS_AES_128_GCM_SHA256"),
                    "Cipher suite negociado debe ser AES-GCM: " + cipher);

            System.out.println("  [OK] Protocolo: " + session.getProtocol());
            System.out.println("  [OK] Cipher Suite: " + cipher);
        }
    }

    // ======================== TEST 2-3: REGISTRO ========================

    @Test
    @Order(2)
    @DisplayName("02 - Registro de nuevo usuario exitoso")
    void testRegistroExitoso() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "REGISTRO|" + TEST_USER + "|" + TEST_PASS);

            assertNotNull(respuesta, "La respuesta no debe ser null");
            assertTrue(respuesta.startsWith("OK|REGISTRO"),
                    "El registro debe ser exitoso. Respuesta: " + respuesta);

            System.out.println("  [OK] Usuario '" + TEST_USER + "' registrado correctamente.");
        }
    }

    @Test
    @Order(3)
    @DisplayName("03 - Registro de usuario duplicado rechazado")
    void testRegistroDuplicado() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "REGISTRO|" + TEST_USER + "|" + TEST_PASS);

            assertNotNull(respuesta, "La respuesta no debe ser null");
            assertTrue(respuesta.startsWith("ERROR|REGISTRO"),
                    "El registro duplicado debe ser rechazado. Respuesta: " + respuesta);

            System.out.println("  [OK] Registro duplicado rechazado correctamente.");
        }
    }

    // ======================== TEST 4-5: LOGIN ========================

    @Test
    @Order(4)
    @DisplayName("04 - Login exitoso con credenciales correctas")
    void testLoginExitoso() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "LOGIN|" + TEST_USER + "|" + TEST_PASS);

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("OK|LOGIN"),
                    "El login debe ser exitoso. Respuesta: " + respuesta);

            System.out.println("  [OK] Login exitoso con credenciales correctas.");

            // Logout para limpiar sesión
            enviarComando(conn, "LOGOUT");
        }
    }

    @Test
    @Order(5)
    @DisplayName("05 - Login con contraseña incorrecta rechazado")
    void testLoginIncorrecto() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "LOGIN|" + TEST_USER + "|ContraseñaMal");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("ERROR|LOGIN"),
                    "El login con contraseña incorrecta debe fallar. Respuesta: " + respuesta);

            System.out.println("  [OK] Login incorrecto rechazado correctamente.");
        }
    }

    // ======================== TEST 6: BRUTE-FORCE ========================

    @Test
    @Order(6)
    @DisplayName("06 - Protección brute-force: bloqueo tras 5 intentos fallidos")
    void testBruteForceBloqueo() throws Exception {
        // Usar un usuario específico para esta prueba (no reutilizar el principal)
        String userBrute = "brutetest_" + System.currentTimeMillis();
        String passReal = "PassBrute1";

        // Primero registrar el usuario
        try (ConexionSSL conn = conectar()) {
            enviarComando(conn, "REGISTRO|" + userBrute + "|" + passReal);
        }

        // Realizar 5 intentos fallidos (cada uno en su propia conexión)
        for (int i = 1; i <= 5; i++) {
            try (ConexionSSL conn = conectar()) {
                String resp = enviarComando(conn, "LOGIN|" + userBrute + "|PasswordIncorrecto");
                assertTrue(resp.startsWith("ERROR|LOGIN"),
                        "Intento #" + i + " debería fallar. Respuesta: " + resp);
            }
        }

        // El 6º intento debe devolver BLOQUEADO
        try (ConexionSSL conn = conectar()) {
            String respBloqueo = enviarComando(conn, "LOGIN|" + userBrute + "|PasswordIncorrecto");

            assertNotNull(respBloqueo);
            assertTrue(respBloqueo.contains("bloqueada") || respBloqueo.contains("BLOQUEADO")
                    || respBloqueo.equals(Protocolo.ERROR_LOGIN_BLOQUEADO),
                    "El 6º intento debe indicar bloqueo. Respuesta: " + respBloqueo);

            System.out.println("  [OK] Bloqueo activado tras 5 intentos fallidos.");
            System.out.println("  [OK] Respuesta: " + respBloqueo);
        }
    }

    // ======================== TEST 7-8: MENSAJES ========================

    @Test
    @Order(7)
    @DisplayName("07 - Envío de mensaje exitoso (≤144 caracteres)")
    void testMensajeExitoso() throws Exception {
        try (ConexionSSL conn = conectar()) {
            // Login primero
            String loginResp = enviarComando(conn, "LOGIN|" + TEST_USER + "|" + TEST_PASS);
            assertTrue(loginResp.startsWith("OK|LOGIN"), "Login debe ser exitoso");

            // Enviar un mensaje válido
            String mensaje = "Hola, este es un mensaje de prueba funcional QA - " + System.currentTimeMillis();
            String respuesta = enviarComando(conn, "MENSAJE|" + mensaje);

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("OK|MENSAJE"),
                    "El mensaje debe ser aceptado. Respuesta: " + respuesta);

            System.out.println("  [OK] Mensaje de " + mensaje.length() + " chars aceptado.");

            enviarComando(conn, "LOGOUT");
        }
    }

    @Test
    @Order(8)
    @DisplayName("08 - Mensaje >144 caracteres rechazado")
    void testMensajeLargo() throws Exception {
        try (ConexionSSL conn = conectar()) {
            // Login primero
            enviarComando(conn, "LOGIN|" + TEST_USER + "|" + TEST_PASS);

            // Generar mensaje de 200 caracteres
            String mensajeLargo = "A".repeat(200);
            String respuesta = enviarComando(conn, "MENSAJE|" + mensajeLargo);

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("ERROR|MENSAJE"),
                    "El mensaje largo debe ser rechazado. Respuesta: " + respuesta);

            System.out.println("  [OK] Mensaje de 200 chars rechazado correctamente.");

            enviarComando(conn, "LOGOUT");
        }
    }

    // ======================== TEST 9: MENSAJE SIN AUTENTICACIÓN
    // ========================

    @Test
    @Order(9)
    @DisplayName("09 - Mensaje sin autenticación rechazado")
    void testMensajeSinLogin() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "MENSAJE|Intento sin login");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("ERROR"),
                    "El mensaje sin login debe ser rechazado. Respuesta: " + respuesta);

            System.out.println("  [OK] Mensaje sin autenticación rechazado.");
        }
    }

    // ======================== TEST 10: HISTORIAL ========================

    @Test
    @Order(10)
    @DisplayName("10 - Historial contiene mensajes enviados")
    void testHistorial() throws Exception {
        try (ConexionSSL conn = conectar()) {
            // Login
            enviarComando(conn, "LOGIN|" + TEST_USER + "|" + TEST_PASS);

            // Enviar un mensaje con texto identificable
            String textoUnico = "QA-HIST-" + System.currentTimeMillis();
            enviarComando(conn, "MENSAJE|" + textoUnico);

            // Consultar historial
            String historial = enviarComando(conn, "HISTORIAL");

            assertNotNull(historial);
            assertTrue(historial.startsWith("OK|HISTORIAL"),
                    "El historial debe comenzar con OK|HISTORIAL. Respuesta: " + historial);
            assertTrue(historial.contains(textoUnico),
                    "El historial debe contener el mensaje enviado: " + textoUnico);

            // Verificar que el total de mensajes es > 0
            assertTrue(historial.contains("Total mensajes:"),
                    "El historial debe incluir el recuento de mensajes.");

            System.out.println("  [OK] Historial contiene el mensaje enviado.");

            enviarComando(conn, "LOGOUT");
        }
    }

    // ======================== TEST 11: LOGOUT ========================

    @Test
    @Order(11)
    @DisplayName("11 - Logout exitoso")
    void testLogout() throws Exception {
        try (ConexionSSL conn = conectar()) {
            // Login
            enviarComando(conn, "LOGIN|" + TEST_USER + "|" + TEST_PASS);

            // Logout
            String respuesta = enviarComando(conn, "LOGOUT");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("OK|LOGOUT"),
                    "El logout debe ser exitoso. Respuesta: " + respuesta);

            System.out.println("  [OK] Logout exitoso.");
        }
    }

    // ======================== TEST 12: LOGOUT SIN SESIÓN ========================

    @Test
    @Order(12)
    @DisplayName("12 - Logout sin sesión activa rechazado")
    void testLogoutSinSesion() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "LOGOUT");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("ERROR|LOGOUT"),
                    "El logout sin sesión debe fallar. Respuesta: " + respuesta);

            System.out.println("  [OK] Logout sin sesión rechazado correctamente.");
        }
    }

    // ======================== TEST 13: COMANDO INVÁLIDO ========================

    @Test
    @Order(13)
    @DisplayName("13 - Comando no reconocido devuelve error")
    void testComandoInvalido() throws Exception {
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "COMANDO_INEXISTENTE|datos");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("ERROR"),
                    "Un comando inválido debe devolver error. Respuesta: " + respuesta);

            System.out.println("  [OK] Comando inválido rechazado correctamente.");
        }
    }

    // ======================== TEST 14: INTEGRIDAD DB (directo)
    // ========================

    @Test
    @Order(14)
    @DisplayName("14 - Integridad de base de datos (HMAC verificado)")
    void testIntegridadBD() throws Exception {
        BaseDatos bd = new BaseDatos();
        bd.inicializar();

        boolean integra = bd.verificarIntegridadCompleta();
        assertTrue(integra,
                "La base de datos debe pasar la verificación de integridad HMAC.");

        System.out.println("  [OK] Integridad HMAC de la base de datos verificada.");
    }

    // ======================== TEST 15: USUARIOS PRE-REGISTRADOS
    // ========================

    @Test
    @Order(15)
    @DisplayName("15 - Usuarios pre-registrados accesibles")
    void testUsuariosPreregistrados() throws Exception {
        // Verificar que el usuario pre-registrado 'admin' puede hacer login
        try (ConexionSSL conn = conectar()) {
            String respuesta = enviarComando(conn, "LOGIN|admin|Admin2024!");

            assertNotNull(respuesta);
            assertTrue(respuesta.startsWith("OK|LOGIN"),
                    "El usuario pre-registrado 'admin' debe poder hacer login. Respuesta: " + respuesta);

            System.out.println("  [OK] Usuario pre-registrado 'admin' accede correctamente.");

            enviarComando(conn, "LOGOUT");
        }
    }
}
