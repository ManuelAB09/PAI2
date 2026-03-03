import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * BaseDatos.java
 * 
 * Capa de persistencia para la VPN SSL BYOD.
 * Utiliza SQLite como motor de base de datos embebido.
 * 
 * Características de seguridad:
 * - Contraseñas almacenadas como hash PBKDF2 + salt (nunca en texto plano)
 * - HMAC-SHA3-256 por cada fila para verificar integridad
 * - Verificación de integridad al arranque del sistema
 * 
 * @author Manuel
 */
public class BaseDatos {

    // ======================== CONSTANTES ========================

    /** URL de conexión a la base de datos SQLite */
    private static final String URL_BD = "jdbc:sqlite:vpn_ssl.db";

    /** Formato de fecha estándar ISO */
    private static final DateTimeFormatter FORMATO_FECHA = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** Usuarios pre-registrados para carga inicial */
    private static final String[][] USUARIOS_INICIALES = {
            { "admin", "Admin2024!" },
            { "usuario1", "Pass_user1" },
            { "usuario2", "Pass_user2" },
            { "usuario3", "Pass_user3" },
            { "usuario4", "Pass_user4" }
    };

    // ======================== INICIALIZACIÓN ========================

    /**
     * Inicializa la base de datos: crea las tablas si no existen
     * y carga los usuarios pre-registrados si la tabla está vacía.
     * También ejecuta la verificación de integridad HMAC.
     */
    public void inicializar() {
        try (Connection conn = obtenerConexion()) {
            crearTablas(conn);
            cargarUsuariosIniciales(conn);
            System.out.println("[BD] Base de datos inicializada correctamente.");
        } catch (SQLException e) {
            System.err.println("[BD] Error al inicializar la base de datos: " + e.getMessage());
            throw new RuntimeException("Error crítico de base de datos", e);
        }
    }

    /**
     * Crea las tablas de usuarios y mensajes si no existen.
     */
    private void crearTablas(Connection conn) throws SQLException {
        String sqlUsuarios = """
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    fecha_registro TEXT NOT NULL,
                    num_mensajes INTEGER DEFAULT 0,
                    hmac TEXT NOT NULL
                )
                """;

        String sqlMensajes = """
                CREATE TABLE IF NOT EXISTS mensajes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER NOT NULL,
                    texto TEXT NOT NULL,
                    fecha_envio TEXT NOT NULL,
                    hmac TEXT NOT NULL,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
                )
                """;

        try (Statement stmt = conn.createStatement()) {
            stmt.execute(sqlUsuarios);
            stmt.execute(sqlMensajes);
        }
    }

    /**
     * Carga los usuarios pre-registrados si la tabla de usuarios está vacía.
     */
    private void cargarUsuariosIniciales(Connection conn) throws SQLException {
        String contarSQL = "SELECT COUNT(*) FROM usuarios";
        try (Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(contarSQL)) {
            if (rs.next() && rs.getInt(1) > 0) {
                System.out.println("[BD] Usuarios existentes encontrados, omitiendo carga inicial.");
                return;
            }
        }

        // Registrar los usuarios iniciales
        for (String[] usuario : USUARIOS_INICIALES) {
            registrarUsuarioInterno(conn, usuario[0], usuario[1]);
        }
        System.out.println("[BD] " + USUARIOS_INICIALES.length + " usuarios pre-registrados cargados.");
    }

    // ======================== OPERACIONES DE USUARIO ========================

    /**
     * Registra un nuevo usuario en la base de datos.
     * 
     * @param username Nombre de usuario (debe ser único)
     * @param password Contraseña en texto plano (será hasheada)
     * @return true si el registro fue exitoso, false si el usuario ya existe
     */
    public boolean registrarUsuario(String username, String password) {
        try (Connection conn = obtenerConexion()) {
            return registrarUsuarioInterno(conn, username, password);
        } catch (SQLException e) {
            System.err.println("[BD] Error al registrar usuario: " + e.getMessage());
            return false;
        }
    }

    /**
     * Método interno para registrar un usuario con una conexión existente.
     */
    private boolean registrarUsuarioInterno(Connection conn, String username, String password) throws SQLException {
        // Verificar si el usuario ya existe
        if (existeUsuario(conn, username)) {
            return false;
        }

        // Generar salt y hash de la contraseña
        byte[] salt = SeguridadUtil.generarSalt();
        String saltBase64 = SeguridadUtil.codificarBase64(salt);
        String hashPassword = SeguridadUtil.hashPassword(password, salt);
        String fechaRegistro = LocalDateTime.now().format(FORMATO_FECHA);

        // Calcular HMAC para integridad de la fila
        String datosParaHMAC = username + "|" + hashPassword + "|" + saltBase64 + "|" + fechaRegistro;
        String hmac = SeguridadUtil.calcularHMAC(datosParaHMAC);

        String sql = "INSERT INTO usuarios (username, password_hash, salt, fecha_registro, num_mensajes, hmac) VALUES (?, ?, ?, ?, 0, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, hashPassword);
            pstmt.setString(3, saltBase64);
            pstmt.setString(4, fechaRegistro);
            pstmt.setString(5, hmac);
            pstmt.executeUpdate();
            System.out.println("[BD] Usuario registrado: " + username);
            return true;
        }
    }

    /**
     * Valida las credenciales de un usuario.
     * Verifica primero la integridad HMAC de la fila y luego la contraseña.
     * 
     * @param username Nombre de usuario
     * @param password Contraseña en texto plano
     * @return El ID del usuario si las credenciales son válidas, -1 en caso
     *         contrario
     */
    public int validarCredenciales(String username, String password) {
        String sql = "SELECT id, password_hash, salt, fecha_registro, hmac FROM usuarios WHERE username = ?";

        try (Connection conn = obtenerConexion();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (!rs.next()) {
                    return -1; // Usuario no encontrado
                }

                int id = rs.getInt("id");
                String hashAlmacenado = rs.getString("password_hash");
                String saltBase64 = rs.getString("salt");
                String fechaRegistro = rs.getString("fecha_registro");
                String hmacAlmacenado = rs.getString("hmac");

                // Verificar integridad HMAC de la fila
                String datosParaHMAC = username + "|" + hashAlmacenado + "|" + saltBase64 + "|" + fechaRegistro;
                if (!SeguridadUtil.verificarHMAC(datosParaHMAC, hmacAlmacenado)) {
                    System.err.println("[SEGURIDAD] ¡ALERTA! Integridad comprometida para usuario: " + username);
                    return -1;
                }

                // Verificar contraseña
                byte[] salt = SeguridadUtil.decodificarBase64(saltBase64);
                if (SeguridadUtil.verificarPassword(password, salt, hashAlmacenado)) {
                    return id;
                }
            }
        } catch (SQLException e) {
            System.err.println("[BD] Error al validar credenciales: " + e.getMessage());
        }
        return -1;
    }

    /**
     * Comprueba si un usuario ya existe en la base de datos.
     */
    private boolean existeUsuario(Connection conn, String username) throws SQLException {
        String sql = "SELECT COUNT(*) FROM usuarios WHERE username = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next() && rs.getInt(1) > 0;
            }
        }
    }

    // ======================== OPERACIONES DE MENSAJES ========================

    /**
     * Guarda un mensaje de texto enviado por un usuario autenticado.
     * Incrementa el contador de mensajes del usuario y verifica la integridad.
     * 
     * @param usuarioId ID del usuario que envía el mensaje
     * @param username  Nombre de usuario (para log)
     * @param texto     Texto del mensaje (máx. 144 caracteres)
     * @return true si el mensaje se guardó correctamente
     */
    public boolean guardarMensaje(int usuarioId, String username, String texto) {
        String fechaEnvio = LocalDateTime.now().format(FORMATO_FECHA);

        // Calcular HMAC para integridad del mensaje
        String datosParaHMAC = usuarioId + "|" + texto + "|" + fechaEnvio;
        String hmac = SeguridadUtil.calcularHMAC(datosParaHMAC);

        String sqlMensaje = "INSERT INTO mensajes (usuario_id, texto, fecha_envio, hmac) VALUES (?, ?, ?, ?)";
        String sqlActualizar = "UPDATE usuarios SET num_mensajes = num_mensajes + 1 WHERE id = ?";

        try (Connection conn = obtenerConexion()) {
            conn.setAutoCommit(false); // Transacción
            try {
                // Insertar mensaje
                try (PreparedStatement pstmt = conn.prepareStatement(sqlMensaje)) {
                    pstmt.setInt(1, usuarioId);
                    pstmt.setString(2, texto);
                    pstmt.setString(3, fechaEnvio);
                    pstmt.setString(4, hmac);
                    pstmt.executeUpdate();
                }

                // Actualizar contador de mensajes
                try (PreparedStatement pstmt = conn.prepareStatement(sqlActualizar)) {
                    pstmt.setInt(1, usuarioId);
                    pstmt.executeUpdate();
                }

                conn.commit();
                System.out.println("[BD] Mensaje almacenado de usuario '" + username + "': " + texto);
                return true;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        } catch (SQLException e) {
            System.err.println("[BD] Error al guardar mensaje: " + e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene el historial de mensajes de un usuario.
     * Verifica la integridad HMAC de cada mensaje.
     * 
     * @param usuarioId ID del usuario
     * @return Lista de cadenas con formato "fecha | texto" o mensaje de error
     */
    public List<String> obtenerHistorial(int usuarioId) {
        List<String> historial = new ArrayList<>();
        String sql = "SELECT texto, fecha_envio, hmac FROM mensajes WHERE usuario_id = ? ORDER BY fecha_envio ASC";

        try (Connection conn = obtenerConexion();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, usuarioId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    String texto = rs.getString("texto");
                    String fechaEnvio = rs.getString("fecha_envio");
                    String hmacAlmacenado = rs.getString("hmac");

                    // Verificar integridad del mensaje
                    String datosParaHMAC = usuarioId + "|" + texto + "|" + fechaEnvio;
                    if (!SeguridadUtil.verificarHMAC(datosParaHMAC, hmacAlmacenado)) {
                        historial.add("[!] ALERTA INTEGRIDAD - " + fechaEnvio + " | Mensaje posiblemente manipulado");
                    } else {
                        historial.add("[" + fechaEnvio + "] " + texto);
                    }
                }
            }
        } catch (SQLException e) {
            System.err.println("[BD] Error al obtener historial: " + e.getMessage());
            historial.add("Error al obtener el historial.");
        }
        return historial;
    }

    /**
     * Obtiene el número total de mensajes enviados por un usuario.
     * 
     * @param usuarioId ID del usuario
     * @return Número de mensajes enviados
     */
    public int obtenerNumMensajes(int usuarioId) {
        String sql = "SELECT num_mensajes FROM usuarios WHERE id = ?";
        try (Connection conn = obtenerConexion();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, usuarioId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("num_mensajes");
                }
            }
        } catch (SQLException e) {
            System.err.println("[BD] Error al obtener número de mensajes: " + e.getMessage());
        }
        return 0;
    }

    // ======================== VERIFICACIÓN DE INTEGRIDAD ========================

    /**
     * Verifica la integridad HMAC de todos los registros de la base de datos.
     * Se ejecuta al arranque del servidor para detectar manipulaciones externas.
     * 
     * @return true si todos los registros son íntegros, false si hay algún problema
     */
    public boolean verificarIntegridadCompleta() {
        boolean integridadOK = true;
        int filasVerificadas = 0;
        int filasCorruptas = 0;

        try (Connection conn = obtenerConexion()) {
            // Verificar usuarios
            String sqlUsuarios = "SELECT username, password_hash, salt, fecha_registro, hmac FROM usuarios";
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(sqlUsuarios)) {
                while (rs.next()) {
                    String username = rs.getString("username");
                    String hash = rs.getString("password_hash");
                    String salt = rs.getString("salt");
                    String fecha = rs.getString("fecha_registro");
                    String hmac = rs.getString("hmac");

                    String datos = username + "|" + hash + "|" + salt + "|" + fecha;
                    if (!SeguridadUtil.verificarHMAC(datos, hmac)) {
                        System.err.println("[SEGURIDAD] ¡INTEGRIDAD COMPROMETIDA! Usuario: " + username);
                        integridadOK = false;
                        filasCorruptas++;
                    }
                    filasVerificadas++;
                }
            }

            // Verificar mensajes
            String sqlMensajes = "SELECT usuario_id, texto, fecha_envio, hmac FROM mensajes";
            try (Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(sqlMensajes)) {
                while (rs.next()) {
                    int usuarioId = rs.getInt("usuario_id");
                    String texto = rs.getString("texto");
                    String fecha = rs.getString("fecha_envio");
                    String hmac = rs.getString("hmac");

                    String datos = usuarioId + "|" + texto + "|" + fecha;
                    if (!SeguridadUtil.verificarHMAC(datos, hmac)) {
                        System.err.println("[SEGURIDAD] ¡INTEGRIDAD COMPROMETIDA! Mensaje ID usuario: " + usuarioId
                                + " fecha: " + fecha);
                        integridadOK = false;
                        filasCorruptas++;
                    }
                    filasVerificadas++;
                }
            }

            if (integridadOK) {
                System.out.println("[SEGURIDAD] Verificación de integridad completada: "
                        + filasVerificadas + " registros verificados. Todo correcto.");
            } else {
                System.err.println("[SEGURIDAD] ¡ALERTA! Se encontraron " + filasCorruptas
                        + " registros con integridad comprometida de " + filasVerificadas + " verificados.");
            }

        } catch (SQLException e) {
            System.err.println("[BD] Error al verificar integridad: " + e.getMessage());
            return false;
        }

        return integridadOK;
    }

    // ======================== CONEXIÓN ========================

    /**
     * Obtiene una conexión a la base de datos SQLite.
     * 
     * @return Conexión JDBC
     * @throws SQLException si no se puede establecer la conexión
     */
    private Connection obtenerConexion() throws SQLException {
        return DriverManager.getConnection(URL_BD);
    }
}
