import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * SeguridadUtil.java
 * 
 * Utilidades de seguridad para la VPN SSL BYOD.
 * Proporciona:
 * - Generación de salt criptográficamente seguro
 * - Hashing de contraseñas con PBKDF2 implementado manualmente sobre
 * HMAC-SHA3-256
 * (310.000 iteraciones, clave de 256 bits)
 * - Verificación de contraseñas con comparación en tiempo constante
 * - Cálculo y verificación de HMAC-SHA3-256 para integridad de base de datos
 * - Gestión de clave HMAC persistente
 * 
 * Nota: Se implementa PBKDF2 manualmente (RFC 8018) porque el proveedor
 * estándar
 * de Java (SunJCE) no incluye "PBKDF2WithHmacSHA3-256" como algoritmo de
 * SecretKeyFactory. Sin embargo, "HmacSHA3-256" sí está disponible desde Java
 * 17+.
 * 
 * @author Manuel
 */
public final class SeguridadUtil {

    // ======================== CONSTANTES ========================

    /** Algoritmo HMAC basado en SHA3-256 (disponible en Java 17+) */
    private static final String ALGORITMO_HMAC = "HmacSHA3-256";

    /** Número de iteraciones PBKDF2 (recomendación OWASP 2024+) */
    private static final int ITERACIONES = 310_000;

    /** Longitud de la clave derivada en bytes (256 bits) */
    private static final int LONGITUD_CLAVE_BYTES = 32;

    /** Tamaño del salt en bytes */
    private static final int TAMANO_SALT = 16;

    /** Tamaño de la clave HMAC para integridad en bytes */
    private static final int TAMANO_CLAVE_HMAC = 32;

    /** Ruta del fichero de clave HMAC */
    private static final String RUTA_CLAVE_HMAC = "hmac.key";

    /** Generador de números aleatorios seguro (thread-safe) */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Clave HMAC cargada en memoria (se inicializa al primer uso) */
    private static byte[] claveHMAC = null;

    // ======================== SALT ========================

    /**
     * Genera un salt criptográficamente seguro de 16 bytes.
     * 
     * @return Array de bytes con el salt generado
     */
    public static byte[] generarSalt() {
        byte[] salt = new byte[TAMANO_SALT];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    // ======================== PBKDF2 MANUAL CON HMAC-SHA3-256
    // ========================

    /**
     * Implementación manual de PBKDF2 (RFC 8018) usando HMAC-SHA3-256 como PRF.
     * 
     * PBKDF2(P, S, c, dkLen) donde:
     * P = contraseña, S = salt, c = iteraciones, dkLen = longitud de la clave
     * derivada
     * 
     * @param password    Contraseña en texto plano
     * @param salt        Salt aleatorio
     * @param iteraciones Número de iteraciones
     * @param dkLen       Longitud de la clave derivada en bytes
     * @return Clave derivada como array de bytes
     */
    private static byte[] pbkdf2HmacSha3_256(char[] password, byte[] salt, int iteraciones, int dkLen) {
        try {
            // Convertir contraseña de char[] a byte[] (UTF-8)
            byte[] passwordBytes = new String(password).getBytes("UTF-8");

            // Longitud de salida del HMAC-SHA3-256 = 32 bytes
            int hLen = 32;

            // Número de bloques necesarios: l = ceil(dkLen / hLen)
            int l = (int) Math.ceil((double) dkLen / hLen);

            byte[] dk = new byte[l * hLen];

            for (int i = 1; i <= l; i++) {
                // U_1 = PRF(Password, Salt || INT_32_BE(i))
                byte[] saltI = new byte[salt.length + 4];
                System.arraycopy(salt, 0, saltI, 0, salt.length);
                // INT_32_BE(i) — codificación big-endian del índice de bloque
                saltI[salt.length] = (byte) (i >> 24);
                saltI[salt.length + 1] = (byte) (i >> 16);
                saltI[salt.length + 2] = (byte) (i >> 8);
                saltI[salt.length + 3] = (byte) (i);

                Mac mac = Mac.getInstance(ALGORITMO_HMAC);
                SecretKeySpec keySpec = new SecretKeySpec(passwordBytes, ALGORITMO_HMAC);
                mac.init(keySpec);

                byte[] u = mac.doFinal(saltI); // U_1
                byte[] resultado = u.clone(); // T_i = U_1

                // U_2 ... U_c
                for (int j = 2; j <= iteraciones; j++) {
                    mac.reset();
                    u = mac.doFinal(u); // U_j = PRF(Password, U_{j-1})
                    // T_i = U_1 XOR U_2 XOR ... XOR U_c
                    for (int k = 0; k < resultado.length; k++) {
                        resultado[k] ^= u[k];
                    }
                }

                // Copiar T_i al resultado final
                System.arraycopy(resultado, 0, dk, (i - 1) * hLen, hLen);
            }

            // Limpiar contraseña de memoria
            Arrays.fill(passwordBytes, (byte) 0);

            // Truncar al tamaño solicitado
            return Arrays.copyOf(dk, dkLen);

        } catch (Exception e) {
            throw new RuntimeException("Error en PBKDF2-HMAC-SHA3-256: " + e.getMessage(), e);
        }
    }

    // ======================== HASHING DE CONTRASEÑAS ========================

    /**
     * Genera el hash de una contraseña usando PBKDF2 con HMAC-SHA3-256.
     * 310.000 iteraciones, clave derivada de 256 bits.
     * 
     * @param password La contraseña en texto plano
     * @param salt     El salt a utilizar
     * @return El hash en formato Base64
     */
    public static String hashPassword(String password, byte[] salt) {
        byte[] hash = pbkdf2HmacSha3_256(
                password.toCharArray(), salt, ITERACIONES, LONGITUD_CLAVE_BYTES);
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Verifica si una contraseña coincide con su hash almacenado.
     * Usa comparación en tiempo constante para evitar ataques de timing.
     * 
     * @param password       La contraseña en texto plano a verificar
     * @param salt           El salt original utilizado
     * @param hashAlmacenado El hash almacenado en Base64
     * @return true si la contraseña es correcta, false en caso contrario
     */
    public static boolean verificarPassword(String password, byte[] salt, String hashAlmacenado) {
        String hashCalculado = hashPassword(password, salt);
        return MessageDigest.isEqual(
                hashCalculado.getBytes(),
                hashAlmacenado.getBytes());
    }

    // ======================== HMAC PARA INTEGRIDAD DE BD ========================

    /**
     * Calcula el HMAC-SHA3-256 de un dato para verificar su integridad.
     * Usa la clave HMAC persistente del sistema.
     * 
     * @param dato El texto sobre el que calcular el HMAC
     * @return El HMAC en formato Base64
     * @throws RuntimeException si hay error al calcular el HMAC
     */
    public static String calcularHMAC(String dato) {
        try {
            byte[] clave = obtenerClaveHMAC();
            Mac mac = Mac.getInstance(ALGORITMO_HMAC);
            SecretKeySpec keySpec = new SecretKeySpec(clave, ALGORITMO_HMAC);
            mac.init(keySpec);
            byte[] hmacBytes = mac.doFinal(dato.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error al calcular HMAC: " + e.getMessage(), e);
        }
    }

    /**
     * Verifica que el HMAC de un dato coincide con el HMAC almacenado.
     * Comparación en tiempo constante.
     * 
     * @param dato           El texto original
     * @param hmacAlmacenado El HMAC almacenado en Base64
     * @return true si el HMAC es válido, false si los datos fueron manipulados
     */
    public static boolean verificarHMAC(String dato, String hmacAlmacenado) {
        String hmacCalculado = calcularHMAC(dato);
        return MessageDigest.isEqual(
                hmacCalculado.getBytes(),
                hmacAlmacenado.getBytes());
    }

    // ======================== GESTIÓN DE CLAVE HMAC ========================

    /**
     * Obtiene la clave HMAC. Si no existe en disco, la genera y la persiste.
     * Se mantiene en memoria una vez cargada para evitar lecturas repetidas.
     * El acceso es synchronized para seguridad en entornos multihilo.
     * 
     * @return La clave HMAC como array de bytes
     * @throws IOException si hay error al leer/escribir el fichero de clave
     */
    private static synchronized byte[] obtenerClaveHMAC() throws IOException {
        if (claveHMAC != null) {
            return claveHMAC;
        }

        Path rutaClave = Paths.get(RUTA_CLAVE_HMAC);

        if (Files.exists(rutaClave)) {
            // Cargar clave existente desde fichero (almacenada en Base64)
            String claveBase64 = new String(Files.readAllBytes(rutaClave)).trim();
            claveHMAC = Base64.getDecoder().decode(claveBase64);
            System.out.println("[SEGURIDAD] Clave HMAC cargada desde fichero.");
        } else {
            // Generar nueva clave aleatoria de 256 bits y guardarla
            claveHMAC = new byte[TAMANO_CLAVE_HMAC];
            SECURE_RANDOM.nextBytes(claveHMAC);
            Files.write(rutaClave, Base64.getEncoder().encode(claveHMAC));
            System.out.println("[SEGURIDAD] Nueva clave HMAC generada y almacenada.");
        }

        return claveHMAC;
    }

    // ======================== UTILIDADES DE CODIFICACIÓN ========================

    /**
     * Codifica un array de bytes a Base64.
     * 
     * @param bytes Array de bytes a codificar
     * @return Cadena en Base64
     */
    public static String codificarBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Decodifica una cadena Base64 a array de bytes.
     * 
     * @param base64 Cadena en Base64
     * @return Array de bytes decodificado
     */
    public static byte[] decodificarBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    /** Constructor privado para evitar instanciación */
    private SeguridadUtil() {
        throw new UnsupportedOperationException("Clase de utilidades, no instanciable.");
    }
}
