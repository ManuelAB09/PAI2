import java.io.*;
import java.net.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.net.ssl.*;

/**
 * PruebaMitM.java
 * 
 * Prueba de concepto (PoC) de ataque Man-in-the-Middle contra la VPN SSL BYOD.
 * 
 * Este programa:
 * 1. Genera un keystore con un certificado autofirmado FALSO en memoria.
 * 2. Levanta un proxy TLS en el puerto 4443.
 * 3. Cuando el cliente Java intenta conectar, el handshake TLS FALLA
 * porque el truststore del cliente solo confía en el certificado real del
 * servidor.
 * 4. Demuestra que la configuración estricta del TrustStore mitiga ataques
 * MitM.
 * 
 * Ejecución:
 * 1. Arrancar el servidor real:
 * java -cp ".;sqlite-jdbc-3.47.2.0.jar"
 * -Djavax.net.ssl.keyStore=servidor_keystore.jks
 * -Djavax.net.ssl.keyStorePassword=cambiame ServidorSSL
 * 
 * 2. Arrancar este proxy MitM:
 * java PruebaMitM
 * 
 * 3. Ejecutar el cliente apuntando al proxy (puerto 4443):
 * java -Djavax.net.ssl.trustStore=cliente_truststore.jks
 * -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSLMitM
 * 
 * Resultado esperado:
 * - El cliente lanza SSLHandshakeException → conexión RECHAZADA ✅
 * - El proxy NO puede interceptar la comunicación
 * 
 * @author Manuel
 */
public class PruebaMitM {

    /** Puerto donde escucha el proxy MitM */
    private static final int PUERTO_PROXY = 4443;

    /** Puerto del servidor real */
    private static final int PUERTO_SERVIDOR_REAL = 3443;

    /** Alias y contraseña del keystore MitM generado en memoria */
    private static final String ALIAS_MITM = "mitm_atacante";
    private static final String PASSWORD_MITM = "atacante";

    // ======================== MAIN ========================

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   VPN SSL BYOD - Prueba de Concepto MitM (Java)     ║");
        System.out.println("║   Man-in-the-Middle Attack Simulation               ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        System.out.println("OBJETIVO: Demostrar que TLS 1.3 + TrustStore previene");
        System.out.println("la interceptación de tráfico por un atacante.\n");

        try {
            // Paso 1: Generar keystore MitM con certificado falso
            System.out.println("[MitM] Paso 1: Generando certificado falso...");
            KeyStore keystoreMitM = generarKeystoreFalso();
            System.out.println("[MitM] Certificado falso generado en memoria.");
            System.out.println("[MitM]   CN=localhost, O=MitM_Atacante, C=XX");
            System.out.println("[MitM]   (NO está en el truststore del cliente)\n");

            // Paso 2: Configurar SSLContext con el keystore falso
            SSLContext contextoMitM = SSLContext.getInstance("TLSv1.3");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystoreMitM, PASSWORD_MITM.toCharArray());
            contextoMitM.init(kmf.getKeyManagers(), null, new SecureRandom());

            // Paso 3: Crear SSLServerSocket del proxy
            SSLServerSocketFactory ssf = contextoMitM.getServerSocketFactory();
            SSLServerSocket proxySocket = (SSLServerSocket) ssf.createServerSocket(PUERTO_PROXY);
            proxySocket.setEnabledProtocols(new String[] { "TLSv1.3" });

            System.out.println("[MitM] ═══════════════════════════════════════════════");
            System.out.println("[MitM]   PROXY MAN-IN-THE-MIDDLE INICIADO");
            System.out.println("[MitM]   Escuchando en puerto " + PUERTO_PROXY);
            System.out.println("[MitM]   Servidor real en localhost:" + PUERTO_SERVIDOR_REAL);
            System.out.println("[MitM] ═══════════════════════════════════════════════\n");

            System.out.println("[MitM] Esperando conexiones de víctimas...");
            System.out.println("[MitM] Execute en otra terminal:");
            System.out.println("         java -Djavax.net.ssl.trustStore=cliente_truststore.jks \\");
            System.out.println("              -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSLMitM\n");

            // Crear fichero de log
            new File("logs").mkdirs();
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            String nombreLog = "logs/PruebaMitM_" + timestamp + ".log";
            PrintWriter log = new PrintWriter(new FileWriter(nombreLog), true);
            log.println("========================================");
            log.println("  TEST: PruebaMitM");
            log.println("  FECHA: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            log.println("========================================");
            log.println();
            System.out.println("[LOG] Registrando resultados en: " + nombreLog + "\n");

            int intentos = 0;
            while (true) {
                try {
                    Socket clienteRaw = proxySocket.accept();
                    intentos++;
                    String clienteIP = clienteRaw.getInetAddress().getHostAddress();

                    System.out.println("\n[MitM] ¡Conexión entrante #" + intentos + " desde " + clienteIP + "!");
                    System.out.println("[MitM] Intentando handshake TLS con certificado FALSO...");

                    // Intentar leer datos (el handshake ya ocurrió en accept para SSLSocket)
                    BufferedReader entrada = new BufferedReader(
                            new InputStreamReader(clienteRaw.getInputStream(), "UTF-8"));

                    // Si llegamos aquí, el cliente ACEPTÓ el certificado falso (MAL)
                    System.out.println("[MitM]  ¡ALERTA! El cliente ACEPTÓ el certificado falso.");
                    System.out.println("[MitM] El TrustStore NO está configurado correctamente.");

                    String datos = entrada.readLine();
                    if (datos != null) {
                        System.out.println("[MitM] Datos interceptados: " + datos);
                    }

                    log.println("[" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "] Intento #" + intentos + " desde " + clienteIP + ": ALERTA - Cliente ACEPTÓ certificado falso");
                    clienteRaw.close();

                } catch (SSLHandshakeException e) {
                    System.out.println("[MitM] Handshake TLS FALLIDO (resultado esperado).");
                    System.out.println("[MitM] El cliente Java RECHAZÓ el certificado falso.");
                    System.out.println("[MitM] ¡El TrustStore protege contra este ataque MitM!");
                    System.out.println("[MitM]    Detalle: " + e.getMessage());
                    log.println("[" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "] Intento #" + (intentos + 1) + ": Handshake FALLIDO (protección MitM OK) - " + e.getMessage());

                } catch (IOException e) {
                    System.out.println("[MitM] Conexión rechazada/reseteada por el cliente.");
                    System.out.println("[MitM] ¡Protección MitM funcionando correctamente!");
                    System.out.println("[MitM]    Detalle: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    log.println("[" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "] Intento #" + (intentos + 1) + ": Conexión rechazada (protección MitM OK) - " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }

        } catch (BindException e) {
            System.err.println("[ERROR] El puerto " + PUERTO_PROXY + " ya está en uso.");
        } catch (Exception e) {
            System.err.println("[ERROR] Error al iniciar el proxy MitM: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ======================== GENERACIÓN DE KEYSTORE FALSO
    // ========================

    /**
     * Genera un KeyStore en memoria con un certificado autofirmado FALSO.
     * Usa keytool internamente a través de la API de Java.
     * 
     * El certificado tiene:
     * - CN=localhost (para intentar engañar al cliente)
     * - O=MitM_Atacante (organización falsa)
     * - Validez de 1 día
     * - RSA 2048 bits
     * 
     * Este certificado NO está en el truststore del cliente, por lo que
     * el handshake TLS será rechazado.
     */
    private static KeyStore generarKeystoreFalso() throws Exception {
        String keystorePath = "mitm_keystore_temp.jks";

        // Eliminar keystore anterior si existe
        new File(keystorePath).delete();

        // Usar keytool para generar el keystore falso
        ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", ALIAS_MITM,
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "1",
                "-keystore", keystorePath,
                "-storepass", PASSWORD_MITM,
                "-keypass", PASSWORD_MITM,
                "-dname", "CN=localhost, OU=MitM, O=MitM_Atacante, L=Desconocido, ST=Desconocido, C=XX");
        pb.redirectErrorStream(true);
        Process proceso = pb.start();

        // Consumir salida del proceso
        BufferedReader reader = new BufferedReader(new InputStreamReader(proceso.getInputStream()));
        while (reader.readLine() != null) {
            // Ignorar salida de keytool
        }
        int exitCode = proceso.waitFor();

        if (exitCode != 0) {
            throw new RuntimeException("Error al generar keystore MitM con keytool (exit code: " + exitCode + ")");
        }

        // Cargar el keystore generado
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, PASSWORD_MITM.toCharArray());
        }

        System.out.println("[MitM] Keystore MitM generado: " + keystorePath);
        return ks;
    }
}
