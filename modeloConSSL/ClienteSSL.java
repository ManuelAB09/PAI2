import java.io.*;
import java.util.Scanner;
import javax.net.ssl.*;

/**
 * ClienteSSL.java
 * 
 * Cliente SSL/TLS para la VPN SSL BYOD.
 * Proporciona un menú interactivo por consola para:
 * - Registrar nuevos usuarios
 * - Iniciar/cerrar sesión
 * - Enviar mensajes de texto (máx. 144 caracteres)
 * - Consultar historial de mensajes
 * 
 * Ejecución:
 * java -Djavax.net.ssl.trustStore=cliente_truststore.jks \
 * -Djavax.net.ssl.trustStorePassword=cambiame \
 * ClienteSSL
 * 
 * @author Manuel
 */
public class ClienteSSL {

    // ======================== CONFIGURACIÓN ========================

    /** Host del servidor */
    private static final String HOST = "localhost";

    /** Protocolos TLS permitidos */
    private static final String[] PROTOCOLOS = { "TLSv1.3" };

    /** Cipher Suites permitidos */
    private static final String[] CIPHER_SUITES = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256"
    };

    // ======================== ESTADO ========================

    /** Indica si el usuario ha iniciado sesión */
    private static boolean sesionActiva = false;

    /** Nombre del usuario autenticado */
    private static String usuarioActual = null;

    // ======================== MAIN ========================

    /**
     * Punto de entrada del cliente SSL.
     * Conecta al servidor y muestra el menú interactivo.
     */
    public static void main(String[] args) {
        System.out.println("============================================");
        System.out.println("   VPN SSL BYOD - Cliente Seguro");
        System.out.println("============================================");
        System.out.println("Conectando a " + HOST + ":" + Protocolo.PUERTO + "...\n");

        try {
            // Crear socket SSL hacia el servidor
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(HOST, Protocolo.PUERTO);

            // Configurar protocolos y cipher suites
            socket.setEnabledProtocols(PROTOCOLOS);
            socket.setEnabledCipherSuites(CIPHER_SUITES);

            // Iniciar handshake TLS
            socket.startHandshake();
            System.out.println("[CLIENTE] Conexión TLS 1.3 establecida con éxito.");
            System.out.println("[CLIENTE] Cipher Suite: " + socket.getSession().getCipherSuite());
            System.out.println();

            // Abrir streams de comunicación
            BufferedReader entrada = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
            PrintWriter salida = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);
            Scanner scanner = new Scanner(System.in);

            // Bucle principal del menú
            boolean ejecutando = true;
            while (ejecutando) {
                mostrarMenu();
                String opcion = scanner.nextLine().trim();

                switch (opcion) {
                    case "1":
                        registrarse(scanner, salida, entrada);
                        break;
                    case "2":
                        iniciarSesion(scanner, salida, entrada);
                        break;
                    case "3":
                        if (sesionActiva) {
                            enviarMensaje(scanner, salida, entrada);
                        } else {
                            // Sin sesión: opción 3 = Salir
                            ejecutando = false;
                            System.out.println("\n[CLIENTE] Desconectando...");
                        }
                        break;
                    case "4":
                        if (sesionActiva) {
                            verHistorial(salida, entrada);
                        } else {
                            System.out.println("\n  Opción no válida. Intente de nuevo.\n");
                        }
                        break;
                    case "5":
                        if (sesionActiva) {
                            cerrarSesion(salida, entrada);
                        } else {
                            System.out.println("\n  Opción no válida. Intente de nuevo.\n");
                        }
                        break;
                    case "6":
                        if (sesionActiva) {
                            // Enviar logout antes de salir
                            cerrarSesion(salida, entrada);
                        }
                        ejecutando = false;
                        System.out.println("\n[CLIENTE] Desconectando...");
                        break;
                    default:
                        System.out.println("\n  Opción no válida. Intente de nuevo.\n");
                }
            }

            // Limpiar recursos
            scanner.close();
            salida.close();
            entrada.close();
            socket.close();
            System.out.println("[CLIENTE] Conexión cerrada. ¡Hasta luego!");

        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.err.println("[ERROR] Fallo en el handshake TLS. Verifique el truststore.");
            System.err.println("  Detalle: " + e.getMessage());
        } catch (java.net.ConnectException e) {
            System.err.println("[ERROR] No se pudo conectar al servidor en " + HOST + ":" + Protocolo.PUERTO);
            System.err.println("  Asegúrese de que el servidor está en ejecución.");
        } catch (IOException e) {
            System.err.println("[ERROR] Error de comunicación: " + e.getMessage());
        }
    }

    // ======================== MENÚ ========================

    /**
     * Muestra el menú principal del cliente.
     * Las opciones 3-5 solo están disponibles si hay sesión activa.
     */
    private static void mostrarMenu() {
        System.out.println("╔════════════════════════════════════════════╗");
        System.out.println("║        VPN SSL BYOD - Menú Principal       ║");
        System.out.println("╠════════════════════════════════════════════╣");

        if (sesionActiva) {
            System.out.println("║  Usuario: " + rellenar(usuarioActual, 32) + "║");
            System.out.println("╠════════════════════════════════════════════╣");
        }

        System.out.println("║  1. Registrarse                            ║");
        System.out.println("║  2. Iniciar sesión                         ║");

        if (sesionActiva) {
            System.out.println("║  3. Enviar mensaje                         ║");
            System.out.println("║  4. Ver historial de mensajes              ║");
            System.out.println("║  5. Cerrar sesión                          ║");
            System.out.println("║  6. Salir                                  ║");
        } else {
            System.out.println("║  3. Salir                                  ║");
        }
        System.out.println("╚════════════════════════════════════════════╝");
        System.out.print("  Seleccione opción: ");
    }

    /**
     * Rellena una cadena con espacios hasta una longitud fija para alineación.
     */
    private static String rellenar(String texto, int longitud) {
        if (texto == null)
            texto = "";
        if (texto.length() >= longitud)
            return texto.substring(0, longitud);
        return texto + " ".repeat(longitud - texto.length());
    }

    // ======================== FUNCIONES DEL MENÚ ========================

    /**
     * Opción 1: Registrar un nuevo usuario.
     */
    private static void registrarse(Scanner scanner, PrintWriter salida, BufferedReader entrada) throws IOException {
        System.out.println("\n--- REGISTRO DE NUEVO USUARIO ---");
        System.out.print("  Nombre de usuario (3-30 caracteres): ");
        String username = scanner.nextLine().trim();

        System.out.print("  Contraseña (mín. 6 caracteres): ");
        String password = scanner.nextLine().trim();

        // Validaciones del lado del cliente
        if (username.isEmpty() || password.isEmpty()) {
            System.out.println("  El nombre de usuario y la contraseña no pueden estar vacíos.\n");
            return;
        }

        if (username.length() < 3 || username.length() > 30) {
            System.out.println("  El nombre de usuario debe tener entre 3 y 30 caracteres.\n");
            return;
        }

        if (password.length() < 6) {
            System.out.println("  La contraseña debe tener al menos 6 caracteres.\n");
            return;
        }

        // Enviar comando al servidor
        String comando = Protocolo.REGISTRO + "|" + username + "|" + password;
        salida.println(comando);

        // Leer respuesta
        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);
    }

    /**
     * Opción 2: Iniciar sesión con credenciales existentes.
     */
    private static void iniciarSesion(Scanner scanner, PrintWriter salida, BufferedReader entrada) throws IOException {
        if (sesionActiva) {
            System.out.println("\n  Ya tiene una sesión activa como '" + usuarioActual + "'. Ciérrela primero.\n");
            return;
        }

        System.out.println("\n--- INICIO DE SESIÓN ---");
        System.out.print("  Nombre de usuario: ");
        String username = scanner.nextLine().trim();

        System.out.print("  Contraseña: ");
        String password = scanner.nextLine().trim();

        if (username.isEmpty() || password.isEmpty()) {
            System.out.println("  Debe proporcionar usuario y contraseña.\n");
            return;
        }

        // Enviar comando al servidor
        String comando = Protocolo.LOGIN + "|" + username + "|" + password;
        salida.println(comando);

        // Leer respuesta
        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);

        // Actualizar estado si el login fue exitoso
        if (respuesta != null && respuesta.startsWith(Protocolo.OK)) {
            sesionActiva = true;
            usuarioActual = username;
        }
    }

    /**
     * Opción 3: Enviar un mensaje de texto.
     */
    private static void enviarMensaje(Scanner scanner, PrintWriter salida, BufferedReader entrada) throws IOException {
        if (!sesionActiva) {
            System.out.println("\n  Debe iniciar sesión primero.\n");
            return;
        }

        System.out.println("\n--- ENVIAR MENSAJE ---");
        System.out.println("  (Máximo " + Protocolo.MAX_LONGITUD_MENSAJE + " caracteres)");
        System.out.print("  Mensaje: ");
        String texto = scanner.nextLine();

        if (texto.trim().isEmpty()) {
            System.out.println("  El mensaje no puede estar vacío.\n");
            return;
        }

        if (texto.length() > Protocolo.MAX_LONGITUD_MENSAJE) {
            System.out.println("  El mensaje excede los " + Protocolo.MAX_LONGITUD_MENSAJE
                    + " caracteres (" + texto.length() + " introducidos).\n");
            return;
        }

        // Enviar comando al servidor
        String comando = Protocolo.MENSAJE + "|" + texto;
        salida.println(comando);

        // Leer respuesta
        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);
    }

    /**
     * Opción 4: Ver el historial de mensajes del usuario actual.
     */
    private static void verHistorial(PrintWriter salida, BufferedReader entrada) throws IOException {
        if (!sesionActiva) {
            System.out.println("\n  Debe iniciar sesión primero.\n");
            return;
        }

        // Enviar comando al servidor
        salida.println(Protocolo.HISTORIAL);

        // Leer respuesta
        String respuesta = entrada.readLine();

        if (respuesta != null && respuesta.startsWith(Protocolo.OK_HISTORIAL)) {
            // Parsear el historial (campos separados por |)
            String[] partes = respuesta.split("\\|");
            System.out.println("\n╔════════════════════════════════════════════╗");
            System.out.println("║          HISTORIAL DE MENSAJES             ║");
            System.out.println("╠════════════════════════════════════════════╣");

            // partes[0] = OK, partes[1] = HISTORIAL, partes[2] = Total mensajes: N
            if (partes.length > 2) {
                System.out.println("║  " + rellenar(partes[2], 42) + "║");
                System.out.println("╠════════════════════════════════════════════╣");
            }

            // Resto son los mensajes
            for (int i = 3; i < partes.length; i++) {
                String msg = partes[i];
                // Dividir mensajes largos en varias líneas si es necesario
                while (msg.length() > 42) {
                    System.out.println("║  " + msg.substring(0, 42) + "║");
                    msg = msg.substring(42);
                }
                System.out.println("║  " + rellenar(msg, 42) + "║");
            }

            System.out.println("╚════════════════════════════════════════════╝\n");
        } else {
            mostrarRespuesta(respuesta);
        }
    }

    /**
     * Opción 5: Cerrar la sesión activa.
     */
    private static void cerrarSesion(PrintWriter salida, BufferedReader entrada) throws IOException {
        if (!sesionActiva) {
            System.out.println("\n  No hay sesión activa.\n");
            return;
        }

        // Enviar comando al servidor
        salida.println(Protocolo.LOGOUT);

        // Leer respuesta
        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);

        // Actualizar estado
        if (respuesta != null && respuesta.startsWith(Protocolo.OK)) {
            sesionActiva = false;
            usuarioActual = null;
        }
    }

    // ======================== UTILIDADES ========================

    /**
     * Muestra la respuesta del servidor de forma formateada.
     * 
     * @param respuesta Respuesta recibida del servidor
     */
    private static void mostrarRespuesta(String respuesta) {
        if (respuesta == null) {
            System.out.println("\n  Sin respuesta del servidor (conexión perdida).\n");
            return;
        }

        String[] partes = respuesta.split("\\|", 3);
        String tipo = partes[0];

        // Obtener el mensaje descriptivo (último campo)
        String mensaje = partes.length >= 3 ? partes[2] : respuesta;

        if (tipo.equals(Protocolo.OK)) {
            System.out.println("\n  " + mensaje + "\n");
        } else if (tipo.equals(Protocolo.ERROR)) {
            System.out.println("\n  " + mensaje + "\n");
        } else {
            System.out.println("\n  [SERVIDOR] " + respuesta + "\n");
        }
    }
}
