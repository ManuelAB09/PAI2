import java.io.*;
import javax.net.ssl.*;

/**
 * ClienteSSLMitM.java
 * 
 * Cliente auxiliar que intenta conectar al proxy MitM (puerto 4443)
 * en lugar del servidor real (puerto 3443).
 * 
 * Se espera que el handshake TLS FALLE porque el certificado del proxy
 * atacante no está en el truststore del cliente (cliente_truststore.jks).
 * 
 * Esto demuestra que la verificación estricta del TrustStore mitiga
 * ataques Man-in-the-Middle.
 * 
 * Ejecución:
 * java -Djavax.net.ssl.trustStore=cliente_truststore.jks
 * -Djavax.net.ssl.trustStorePassword=cambiame
 * ClienteSSLMitM
 * 
 * @author Manuel
 */
public class ClienteSSLMitM {

    /** Puerto del proxy MitM (NO el servidor real) */
    private static final int PUERTO_MITM = 4443;

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   Prueba MitM — Cliente conectando al ATACANTE      ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        System.out.println("[CLIENTE] Intentando conectar a localhost:" + PUERTO_MITM
                + " (proxy MitM)...\n");

        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket("localhost", PUERTO_MITM);
            socket.setEnabledProtocols(new String[] { "TLSv1.3" });

            System.out.println("[CLIENTE] Iniciando handshake TLS con el proxy MitM...");
            socket.startHandshake();

            System.out.println("\n ¡ALERTA! El handshake fue EXITOSO con el proxy atacante.");
            System.out.println(" El TrustStore NO está configurado correctamente.");
            System.out.println(" Un atacante podría interceptar toda la comunicación.\n");

            PrintWriter salida = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);
            salida.println("LOGIN|admin|Admin2024!");
            System.out.println("[CLIENTE] ¡Credenciales enviadas al atacante sin protección!");

            socket.close();

        } catch (SSLHandshakeException e) {
            System.out.println("╔══════════════════════════════════════════════════════╗");
            System.out.println("║   RESULTADO: PROTECCIÓN MitM ACTIVA               ║");
            System.out.println("╠══════════════════════════════════════════════════════╣");
            System.out.println("║                                                      ║");
            System.out.println("║  SSLHandshakeException capturada correctamente.      ║");
            System.out.println("║  El cliente RECHAZÓ el certificado FALSO.            ║");
            System.out.println("║  El TrustStore protege contra ataques MitM.          ║");
            System.out.println("║                                                      ║");
            System.out.println("╚══════════════════════════════════════════════════════╝");
            System.out.println("\n[DETALLE] Excepción:");
            System.out.println("  Tipo: " + e.getClass().getName());
            System.out.println("  Mensaje: " + e.getMessage());

        } catch (java.net.ConnectException e) {
            System.out.println("[ERROR] No se pudo conectar al proxy MitM en puerto " + PUERTO_MITM);
            System.out.println("  Asegúrese de que PruebaMitM.java está en ejecución.");

        } catch (IOException e) {
            System.out.println("[ERROR] Error de comunicación: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }
    }
}
