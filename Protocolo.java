/**
 * Protocolo.java
 * 
 * Constantes compartidas entre el servidor y el cliente SSL.
 * Define los comandos del protocolo de comunicación, los prefijos de respuesta
 * y el delimitador de campos para la VPN SSL BYOD.
 * 
 * @author Manuel
 */
public final class Protocolo {

    // ======================== COMANDOS DEL CLIENTE ========================

    /** Comando para registrar un nuevo usuario */
    public static final String REGISTRO = "REGISTRO";

    /** Comando para iniciar sesión */
    public static final String LOGIN = "LOGIN";

    /** Comando para cerrar sesión */
    public static final String LOGOUT = "LOGOUT";

    /** Comando para enviar un mensaje de texto */
    public static final String MENSAJE = "MENSAJE";

    /** Comando para consultar el historial de mensajes */
    public static final String HISTORIAL = "HISTORIAL";

    // ======================== PREFIJOS DE RESPUESTA ========================

    /** Prefijo para respuestas exitosas */
    public static final String OK = "OK";

    /** Prefijo para respuestas de error */
    public static final String ERROR = "ERROR";

    // ======================== RESPUESTAS ESPECÍFICAS ========================

    public static final String OK_REGISTRO = "OK|REGISTRO|Usuario registrado correctamente.";
    public static final String ERROR_REGISTRO_EXISTE = "ERROR|REGISTRO|El nombre de usuario ya existe.";
    public static final String ERROR_REGISTRO_DATOS = "ERROR|REGISTRO|Datos de registro inválidos.";

    public static final String OK_LOGIN = "OK|LOGIN|Inicio de sesión exitoso.";
    public static final String ERROR_LOGIN_CRED = "ERROR|LOGIN|Credenciales incorrectas.";
    public static final String ERROR_LOGIN_BLOQUEADO = "ERROR|LOGIN|Cuenta bloqueada temporalmente por múltiples intentos fallidos. Espere 30 segundos.";
    public static final String ERROR_LOGIN_YA_AUTENTICADO = "ERROR|LOGIN|Ya hay una sesión activa.";

    public static final String OK_LOGOUT = "OK|LOGOUT|Sesión cerrada correctamente.";
    public static final String ERROR_LOGOUT = "ERROR|LOGOUT|No hay sesión activa.";

    public static final String OK_MENSAJE = "OK|MENSAJE|Mensaje recibido y almacenado.";
    public static final String ERROR_MENSAJE_LONG = "ERROR|MENSAJE|El mensaje excede los 144 caracteres.";
    public static final String ERROR_MENSAJE_VACIO = "ERROR|MENSAJE|El mensaje no puede estar vacío.";
    public static final String ERROR_NO_AUTENTICADO = "ERROR|SESION|Debe iniciar sesión primero.";

    public static final String OK_HISTORIAL = "OK|HISTORIAL";
    public static final String ERROR_HISTORIAL = "ERROR|HISTORIAL|No se pudo obtener el historial.";

    public static final String ERROR_COMANDO = "ERROR|COMANDO|Comando no reconocido.";
    public static final String ERROR_INTERNO = "ERROR|INTERNO|Error interno del servidor.";

    // ======================== CONFIGURACIÓN ========================

    /** Delimitador de campos en los mensajes del protocolo */
    public static final String DELIMITADOR = "|";

    /** Longitud máxima del mensaje de texto */
    public static final int MAX_LONGITUD_MENSAJE = 144;

    /** Puerto del servidor SSL */
    public static final int PUERTO = 3443;

    /** Número máximo de intentos de login antes de bloqueo */
    public static final int MAX_INTENTOS_LOGIN = 5;

    /** Duración del bloqueo por fuerza bruta en milisegundos (30 segundos) */
    public static final long DURACION_BLOQUEO_MS = 30_000;

    /** Constructor privado para evitar instanciación */
    private Protocolo() {
        throw new UnsupportedOperationException("Clase de constantes, no instanciable.");
    }
}
