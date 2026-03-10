import java.io.*;
import java.net.*;
import java.util.Scanner;

/**
 * ClienteSinSSL.java
 * 
 * Versión SIN TLS del cliente para la VPN SSL BYOD.
 * Usa sockets TCP planos (sin cifrado) para medir tiempos
 * y comparar rendimiento con la versión SSL/TLS.
 * 
 * Ejecución:
 * java ClienteSinSSL
 * 
 * @author Manuel
 */
public class ClienteSinSSL {

    // ======================== CONFIGURACIÓN ========================

    /** Host del servidor */
    private static final String HOST = "localhost";

    /** Puerto del servidor sin SSL (debe coincidir con ServidorSinSSL) */
    private static final int PUERTO_SIN_SSL = 3080;

    // ======================== ESTADO ========================

    /** Indica si el usuario ha iniciado sesión */
    private static boolean sesionActiva = false;

    /** Nombre del usuario autenticado */
    private static String usuarioActual = null;

    // ======================== MAIN ========================

    public static void main(String[] args) {
        System.out.println("============================================");
        System.out.println("   VPN BYOD - Cliente SIN SSL (benchmark)");
        System.out.println("============================================");
        System.out.println("Conectando a " + HOST + ":" + PUERTO_SIN_SSL + "...\n");

        try {
            // Crear socket TCP plano (sin SSL)
            Socket socket = new Socket(HOST, PUERTO_SIN_SSL);

            System.out.println("[CLIENTE] Conexión TCP plana establecida (sin cifrado).");
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

        } catch (java.net.ConnectException e) {
            System.err.println("[ERROR] No se pudo conectar al servidor en " + HOST + ":" + PUERTO_SIN_SSL);
            System.err.println("  Asegúrese de que ServidorSinSSL está en ejecución.");
        } catch (IOException e) {
            System.err.println("[ERROR] Error de comunicación: " + e.getMessage());
        }
    }

    // ======================== MENÚ ========================

    private static void mostrarMenu() {
        System.out.println("╔════════════════════════════════════════════╗");
        System.out.println("║    VPN BYOD - Menú (SIN SSL - benchmark)   ║");
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

    private static String rellenar(String texto, int longitud) {
        if (texto == null)
            texto = "";
        if (texto.length() >= longitud)
            return texto.substring(0, longitud);
        return texto + " ".repeat(longitud - texto.length());
    }

    // ======================== FUNCIONES DEL MENÚ ========================

    private static void registrarse(Scanner scanner, PrintWriter salida, BufferedReader entrada) throws IOException {
        System.out.println("\n--- REGISTRO DE NUEVO USUARIO ---");
        System.out.print("  Nombre de usuario (3-30 caracteres): ");
        String username = scanner.nextLine().trim();

        System.out.print("  Contraseña (mín. 6 caracteres): ");
        String password = scanner.nextLine().trim();

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

        String comando = Protocolo.REGISTRO + "|" + username + "|" + password;
        salida.println(comando);

        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);
    }

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

        String comando = Protocolo.LOGIN + "|" + username + "|" + password;
        salida.println(comando);

        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);

        if (respuesta != null && respuesta.startsWith(Protocolo.OK)) {
            sesionActiva = true;
            usuarioActual = username;
        }
    }

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

        String comando = Protocolo.MENSAJE + "|" + texto;
        salida.println(comando);

        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);
    }

    private static void verHistorial(PrintWriter salida, BufferedReader entrada) throws IOException {
        if (!sesionActiva) {
            System.out.println("\n  Debe iniciar sesión primero.\n");
            return;
        }

        salida.println(Protocolo.HISTORIAL);

        String respuesta = entrada.readLine();

        if (respuesta != null && respuesta.startsWith(Protocolo.OK_HISTORIAL)) {
            String[] partes = respuesta.split("\\|");
            System.out.println("\n╔════════════════════════════════════════════╗");
            System.out.println("║          HISTORIAL DE MENSAJES             ║");
            System.out.println("╠════════════════════════════════════════════╣");

            if (partes.length > 2) {
                System.out.println("║  " + rellenar(partes[2], 42) + "║");
                System.out.println("╠════════════════════════════════════════════╣");
            }

            for (int i = 3; i < partes.length; i++) {
                String msg = partes[i];
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

    private static void cerrarSesion(PrintWriter salida, BufferedReader entrada) throws IOException {
        if (!sesionActiva) {
            System.out.println("\n  No hay sesión activa.\n");
            return;
        }

        salida.println(Protocolo.LOGOUT);

        String respuesta = entrada.readLine();
        mostrarRespuesta(respuesta);

        if (respuesta != null && respuesta.startsWith(Protocolo.OK)) {
            sesionActiva = false;
            usuarioActual = null;
        }
    }

    // ======================== UTILIDADES ========================

    private static void mostrarRespuesta(String respuesta) {
        if (respuesta == null) {
            System.out.println("\n  Sin respuesta del servidor (conexión perdida).\n");
            return;
        }

        String[] partes = respuesta.split("\\|", 3);
        String tipo = partes[0];

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
