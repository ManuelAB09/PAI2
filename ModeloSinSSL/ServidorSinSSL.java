import java.io.*;
import java.net.*;
import java.util.List;
import java.util.concurrent.*;

/**
 * ServidorSinSSL.java
 * 
 * Versión SIN TLS del servidor para la VPN SSL BYOD.
 * Usa sockets TCP planos (sin cifrado) para medir tiempos
 * y comparar rendimiento con la versión SSL/TLS.
 * 
 * Ejecución:
 * java -cp ".;sqlite-jdbc-3.47.2.0.jar" ServidorSinSSL
 * 
 * @author Manuel
 */
public class ServidorSinSSL {

    // ======================== CONFIGURACIÓN ========================

    /** Puerto para la versión sin SSL (diferente al SSL para poder coexistir) */
    private static final int PUERTO_SIN_SSL = 3080;

    /** Tamaño del pool de hilos */
    private static final int TAMANO_POOL = 300;

    // ======================== ESTADO DEL SERVIDOR ========================

    /** Base de datos para persistencia */
    private static final BaseDatos baseDatos = new BaseDatos();

    /** Mapa de protección contra fuerza bruta */
    private static final ConcurrentHashMap<String, int[]> intentosFallidos = new ConcurrentHashMap<>();

    /** Mapa de timestamps de bloqueo por usuario */
    private static final ConcurrentHashMap<String, Long> timestampBloqueo = new ConcurrentHashMap<>();

    // ======================== MAIN ========================

    public static void main(String[] args) {
        System.out.println("============================================");
        System.out.println("   VPN BYOD - Servidor SIN SSL (benchmark)");
        System.out.println("============================================");

        // Inicializar base de datos y verificar integridad
        baseDatos.inicializar();
        baseDatos.verificarIntegridadCompleta();

        // Pool de hilos para concurrencia
        ExecutorService pool = Executors.newFixedThreadPool(TAMANO_POOL);

        try {
            // Crear socket TCP plano (sin SSL)
            ServerSocket serverSocket = new ServerSocket(PUERTO_SIN_SSL, 500);

            System.out.println("[SERVIDOR] Servidor SIN SSL iniciado en puerto " + PUERTO_SIN_SSL);
            System.out.println("[SERVIDOR] Protocolo: TCP plano (sin cifrado)");
            System.out.println("[SERVIDOR] Pool de hilos: " + TAMANO_POOL + " hilos");
            System.out.println("[SERVIDOR] Esperando conexiones...\n");

            // Bucle principal: aceptar conexiones indefinidamente
            while (true) {
                try {
                    Socket clienteSocket = serverSocket.accept();
                    String clienteIP = clienteSocket.getInetAddress().getHostAddress();
                    System.out.println("[SERVIDOR] Nueva conexión desde: " + clienteIP);
                    pool.execute(new ManejadorCliente(clienteSocket, clienteIP));
                } catch (IOException e) {
                    System.err.println("[SERVIDOR] Error al aceptar conexión: " + e.getMessage());
                }
            }

        } catch (IOException e) {
            System.err.println("[SERVIDOR] Error fatal al iniciar el servidor: " + e.getMessage());
            e.printStackTrace();
        } finally {
            pool.shutdown();
        }
    }

    // ======================== PROTECCIÓN BRUTE-FORCE ========================

    private static boolean estaBloqueado(String username) {
        Long timestamp = timestampBloqueo.get(username);
        if (timestamp == null) {
            return false;
        }

        if (System.currentTimeMillis() - timestamp > Protocolo.DURACION_BLOQUEO_MS) {
            intentosFallidos.remove(username);
            timestampBloqueo.remove(username);
            return false;
        }

        return true;
    }

    private static void registrarIntentoFallido(String username) {
        int[] intentos = intentosFallidos.computeIfAbsent(username, k -> new int[] { 0 });
        intentos[0]++;

        System.out.println("[SEGURIDAD] Intento fallido #" + intentos[0] + " para usuario: " + username);

        if (intentos[0] >= Protocolo.MAX_INTENTOS_LOGIN) {
            timestampBloqueo.put(username, System.currentTimeMillis());
            System.out.println("[SEGURIDAD] ¡Usuario '" + username + "' BLOQUEADO por "
                    + (Protocolo.DURACION_BLOQUEO_MS / 1000) + " segundos!");
        }
    }

    private static void resetearIntentos(String username) {
        intentosFallidos.remove(username);
        timestampBloqueo.remove(username);
    }

    // ======================== MANEJADOR DE CLIENTE ========================

    private static class ManejadorCliente implements Runnable {

        private final Socket socket;
        private final String clienteIP;
        private String usuarioActual = null;
        private int usuarioIdActual = -1;

        public ManejadorCliente(Socket socket, String clienteIP) {
            this.socket = socket;
            this.clienteIP = clienteIP;
        }

        @Override
        public void run() {
            try (
                    BufferedReader entrada = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), "UTF-8"));
                    PrintWriter salida = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"),
                            true)) {
                String linea;
                while ((linea = entrada.readLine()) != null) {
                    String respuesta = procesarComando(linea.trim());
                    salida.println(respuesta);

                    if (linea.trim().startsWith(Protocolo.LOGOUT)) {
                        break;
                    }
                }
            } catch (IOException e) {
                System.out.println("[SERVIDOR] Cliente desconectado (" + clienteIP + "): " + e.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    // Ignorar error al cerrar
                }
                if (usuarioActual != null) {
                    System.out.println("[SERVIDOR] Sesión finalizada para usuario: " + usuarioActual);
                }
                System.out.println("[SERVIDOR] Conexión cerrada con: " + clienteIP);
            }
        }

        private String procesarComando(String comando) {
            if (comando.isEmpty()) {
                return Protocolo.ERROR_COMANDO;
            }

            String[] partes = comando.split("\\|", -1);
            String accion = partes[0].toUpperCase();

            switch (accion) {
                case Protocolo.REGISTRO:
                    return procesarRegistro(partes);
                case Protocolo.LOGIN:
                    return procesarLogin(partes);
                case Protocolo.LOGOUT:
                    return procesarLogout();
                case Protocolo.MENSAJE:
                    return procesarMensaje(partes);
                case Protocolo.HISTORIAL:
                    return procesarHistorial();
                default:
                    return Protocolo.ERROR_COMANDO;
            }
        }

        private String procesarRegistro(String[] partes) {
            if (partes.length < 3) {
                return Protocolo.ERROR_REGISTRO_DATOS;
            }

            String username = partes[1].trim();
            String password = partes[2].trim();

            if (username.isEmpty() || password.isEmpty()) {
                return Protocolo.ERROR_REGISTRO_DATOS;
            }

            if (username.length() < 3 || username.length() > 30) {
                return "ERROR|REGISTRO|El nombre de usuario debe tener entre 3 y 30 caracteres.";
            }

            if (password.length() < 6) {
                return "ERROR|REGISTRO|La contraseña debe tener al menos 6 caracteres.";
            }

            boolean exito = baseDatos.registrarUsuario(username, password);
            if (exito) {
                System.out.println("[SERVIDOR] Registro exitoso: " + username + " desde " + clienteIP);
                return Protocolo.OK_REGISTRO;
            } else {
                System.out.println("[SERVIDOR] Registro fallido (ya existe): " + username);
                return Protocolo.ERROR_REGISTRO_EXISTE;
            }
        }

        private String procesarLogin(String[] partes) {
            if (usuarioActual != null) {
                return Protocolo.ERROR_LOGIN_YA_AUTENTICADO;
            }

            if (partes.length < 3) {
                return Protocolo.ERROR_LOGIN_CRED;
            }

            String username = partes[1].trim();
            String password = partes[2].trim();

            if (estaBloqueado(username)) {
                System.out.println("[SEGURIDAD] Intento de login en cuenta bloqueada: " + username);
                return Protocolo.ERROR_LOGIN_BLOQUEADO;
            }

            int userId = baseDatos.validarCredenciales(username, password);
            if (userId > 0) {
                usuarioActual = username;
                usuarioIdActual = userId;
                resetearIntentos(username);
                System.out.println("[SERVIDOR] Login exitoso: " + username + " desde " + clienteIP);
                return Protocolo.OK_LOGIN;
            } else {
                registrarIntentoFallido(username);
                System.out.println("[SERVIDOR] Login fallido: " + username + " desde " + clienteIP);
                return Protocolo.ERROR_LOGIN_CRED;
            }
        }

        private String procesarLogout() {
            if (usuarioActual == null) {
                return Protocolo.ERROR_LOGOUT;
            }

            System.out.println("[SERVIDOR] Logout: " + usuarioActual);
            usuarioActual = null;
            usuarioIdActual = -1;
            return Protocolo.OK_LOGOUT;
        }

        private String procesarMensaje(String[] partes) {
            if (usuarioActual == null) {
                return Protocolo.ERROR_NO_AUTENTICADO;
            }

            if (partes.length < 2) {
                return Protocolo.ERROR_MENSAJE_VACIO;
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 1; i < partes.length; i++) {
                if (i > 1)
                    sb.append("|");
                sb.append(partes[i]);
            }
            String texto = sb.toString().trim();

            if (texto.isEmpty()) {
                return Protocolo.ERROR_MENSAJE_VACIO;
            }

            if (texto.length() > Protocolo.MAX_LONGITUD_MENSAJE) {
                return Protocolo.ERROR_MENSAJE_LONG;
            }

            boolean exito = baseDatos.guardarMensaje(usuarioIdActual, usuarioActual, texto);
            if (exito) {
                return Protocolo.OK_MENSAJE;
            } else {
                return Protocolo.ERROR_INTERNO;
            }
        }

        private String procesarHistorial() {
            if (usuarioActual == null) {
                return Protocolo.ERROR_NO_AUTENTICADO;
            }

            List<String> historial = baseDatos.obtenerHistorial(usuarioIdActual);
            int numMensajes = baseDatos.obtenerNumMensajes(usuarioIdActual);

            StringBuilder respuesta = new StringBuilder();
            respuesta.append(Protocolo.OK_HISTORIAL);
            respuesta.append("|Total mensajes: ").append(numMensajes);

            if (historial.isEmpty()) {
                respuesta.append("|No hay mensajes en el historial.");
            } else {
                for (String mensaje : historial) {
                    respuesta.append("|").append(mensaje);
                }
            }

            return respuesta.toString();
        }
    }
}
