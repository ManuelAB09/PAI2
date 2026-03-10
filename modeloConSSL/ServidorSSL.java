import java.io.*;
import java.util.List;
import java.util.concurrent.*;
import javax.net.ssl.*;

/**
 * ServidorSSL.java
 * 
 * Servidor SSL/TLS para la VPN SSL BYOD.
 * 
 * Características:
 * - Comunicación exclusivamente TLS 1.3
 * - Cipher Suites robustos: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256
 * - Pool de hilos para ~300 clientes concurrentes (ExecutorService)
 * - Protección contra fuerza bruta (bloqueo temporal tras 5 intentos fallidos)
 * - Persistencia con SQLite + HMAC de integridad
 * - Hashing de contraseñas con PBKDF2 + SHA3-256
 * 
 * Ejecución:
 * java -cp ".;sqlite-jdbc-3.47.2.0.jar" \
 * -Djavax.net.ssl.keyStore=servidor_keystore.jks \
 * -Djavax.net.ssl.keyStorePassword=cambiame \
 * ServidorSSL
 * 
 * @author Manuel
 */
public class ServidorSSL {

    // ======================== CONFIGURACIÓN ========================

    /** Protocolos TLS permitidos (solo TLS 1.3) */
    private static final String[] PROTOCOLOS = { "TLSv1.3" };

    /** Cipher Suites permitidos (AES-GCM robustos) */
    private static final String[] CIPHER_SUITES = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256"
    };

    /** Tamaño del pool de hilos */
    private static final int TAMANO_POOL = 300;

    // ======================== ESTADO DEL SERVIDOR ========================

    /** Base de datos para persistencia */
    private static final BaseDatos baseDatos = new BaseDatos();

    /**
     * Mapa de protección contra fuerza bruta.
     * Clave: nombre de usuario
     * Valor: int[2] donde [0] = intentos fallidos, [1] no usado (timestamp en long
     * abajo)
     */
    private static final ConcurrentHashMap<String, int[]> intentosFallidos = new ConcurrentHashMap<>();

    /**
     * Mapa de timestamps de bloqueo por usuario.
     * Clave: nombre de usuario
     * Valor: timestamp (ms) del último intento fallido que causó bloqueo
     */
    private static final ConcurrentHashMap<String, Long> timestampBloqueo = new ConcurrentHashMap<>();

    // ======================== MAIN ========================

    /**
     * Punto de entrada del servidor SSL.
     * Inicializa la base de datos, configura el socket SSL y acepta conexiones.
     */
    public static void main(String[] args) {
        System.out.println("============================================");
        System.out.println("   VPN SSL BYOD - Servidor Seguro");
        System.out.println("============================================");

        // Inicializar base de datos y verificar integridad
        baseDatos.inicializar();
        baseDatos.verificarIntegridadCompleta();

        // Pool de hilos para concurrencia
        ExecutorService pool = Executors.newFixedThreadPool(TAMANO_POOL);

        try {
            // Crear socket SSL del servidor
            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(Protocolo.PUERTO, 500);

            // Configurar protocolos y cipher suites
            serverSocket.setEnabledProtocols(PROTOCOLOS);
            serverSocket.setEnabledCipherSuites(CIPHER_SUITES);
            serverSocket.setNeedClientAuth(false);

            System.out.println("[SERVIDOR] Servidor SSL iniciado en puerto " + Protocolo.PUERTO);
            System.out.println("[SERVIDOR] Protocolo: TLS 1.3");
            System.out.println("[SERVIDOR] Cipher Suites: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256");
            System.out.println("[SERVIDOR] Pool de hilos: " + TAMANO_POOL + " hilos");
            System.out.println("[SERVIDOR] Esperando conexiones...\n");

            // Bucle principal: aceptar conexiones indefinidamente
            while (true) {
                try {
                    SSLSocket clienteSocket = (SSLSocket) serverSocket.accept();
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

    /**
     * Verifica si un usuario está bloqueado por intentos fallidos.
     * 
     * @param username Nombre de usuario a verificar
     * @return true si el usuario está bloqueado
     */
    private static boolean estaBloqueado(String username) {
        Long timestamp = timestampBloqueo.get(username);
        if (timestamp == null) {
            return false;
        }

        // Verificar si el bloqueo ha expirado
        if (System.currentTimeMillis() - timestamp > Protocolo.DURACION_BLOQUEO_MS) {
            // Bloqueo expirado, resetear contadores
            intentosFallidos.remove(username);
            timestampBloqueo.remove(username);
            return false;
        }

        return true;
    }

    /**
     * Registra un intento de login fallido y activa bloqueo si es necesario.
     * 
     * @param username Nombre de usuario
     */
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

    /**
     * Resetea el contador de intentos fallidos tras un login exitoso.
     * 
     * @param username Nombre de usuario
     */
    private static void resetearIntentos(String username) {
        intentosFallidos.remove(username);
        timestampBloqueo.remove(username);
    }

    // ======================== MANEJADOR DE CLIENTE ========================

    /**
     * Clase interna que maneja la comunicación con un cliente individual.
     * Implementa Runnable para ejecutarse en el pool de hilos.
     */
    private static class ManejadorCliente implements Runnable {

        private final SSLSocket socket;
        private final String clienteIP;
        private String usuarioActual = null;
        private int usuarioIdActual = -1;

        /**
         * Constructor del manejador de cliente.
         * 
         * @param socket    Socket SSL del cliente
         * @param clienteIP Dirección IP del cliente
         */
        public ManejadorCliente(SSLSocket socket, String clienteIP) {
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

                    // Si fue LOGOUT, terminar la conexión
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

        /**
         * Procesa un comando recibido del cliente y devuelve la respuesta.
         * 
         * @param comando Línea de comando recibida
         * @return Cadena de respuesta para el cliente
         */
        private String procesarComando(String comando) {
            if (comando.isEmpty()) {
                return Protocolo.ERROR_COMANDO;
            }

            // Parsear comando y parámetros (separados por |)
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

        /**
         * Procesa el comando REGISTRO|username|password
         */
        private String procesarRegistro(String[] partes) {
            if (partes.length < 3) {
                return Protocolo.ERROR_REGISTRO_DATOS;
            }

            String username = partes[1].trim();
            String password = partes[2].trim();

            // Validaciones básicas
            if (username.isEmpty() || password.isEmpty()) {
                return Protocolo.ERROR_REGISTRO_DATOS;
            }

            if (username.length() < 3 || username.length() > 30) {
                return "ERROR|REGISTRO|El nombre de usuario debe tener entre 3 y 30 caracteres.";
            }

            if (password.length() < 6) {
                return "ERROR|REGISTRO|La contraseña debe tener al menos 6 caracteres.";
            }

            // Intentar registrar
            boolean exito = baseDatos.registrarUsuario(username, password);
            if (exito) {
                System.out.println("[SERVIDOR] Registro exitoso: " + username + " desde " + clienteIP);
                return Protocolo.OK_REGISTRO;
            } else {
                System.out.println("[SERVIDOR] Registro fallido (ya existe): " + username);
                return Protocolo.ERROR_REGISTRO_EXISTE;
            }
        }

        /**
         * Procesa el comando LOGIN|username|password
         * Incluye protección contra fuerza bruta.
         */
        private String procesarLogin(String[] partes) {
            // Verificar si ya está autenticado
            if (usuarioActual != null) {
                return Protocolo.ERROR_LOGIN_YA_AUTENTICADO;
            }

            if (partes.length < 3) {
                return Protocolo.ERROR_LOGIN_CRED;
            }

            String username = partes[1].trim();
            String password = partes[2].trim();

            // Verificar bloqueo por fuerza bruta
            if (estaBloqueado(username)) {
                System.out.println("[SEGURIDAD] Intento de login en cuenta bloqueada: " + username);
                return Protocolo.ERROR_LOGIN_BLOQUEADO;
            }

            // Validar credenciales
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

        /**
         * Procesa el comando LOGOUT
         */
        private String procesarLogout() {
            if (usuarioActual == null) {
                return Protocolo.ERROR_LOGOUT;
            }

            System.out.println("[SERVIDOR] Logout: " + usuarioActual);
            usuarioActual = null;
            usuarioIdActual = -1;
            return Protocolo.OK_LOGOUT;
        }

        /**
         * Procesa el comando MENSAJE|texto
         */
        private String procesarMensaje(String[] partes) {
            if (usuarioActual == null) {
                return Protocolo.ERROR_NO_AUTENTICADO;
            }

            if (partes.length < 2) {
                return Protocolo.ERROR_MENSAJE_VACIO;
            }

            // Reconstruir el texto del mensaje (puede contener el delimitador)
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

            // Guardar mensaje en base de datos
            boolean exito = baseDatos.guardarMensaje(usuarioIdActual, usuarioActual, texto);
            if (exito) {
                return Protocolo.OK_MENSAJE;
            } else {
                return Protocolo.ERROR_INTERNO;
            }
        }

        /**
         * Procesa el comando HISTORIAL
         * Devuelve el historial de mensajes del usuario autenticado.
         */
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
