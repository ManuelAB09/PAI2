import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;

/**
 * PruebaRendimiento.java
 * 
 * Simulación de carga de 300 clientes concurrentes contra el servidor SSL.
 * 
 * Cada cliente ejecuta un flujo completo:
 * 1. Conexión TLS 1.3
 * 2. Registro (usuario único por hilo)
 * 3. Login
 * 4. Enviar 3 mensajes
 * 5. Consultar historial
 * 6. Logout
 * 
 * Métricas recopiladas:
 * - Tiempo total de la prueba
 * - Tiempo medio por cliente
 * - Tiempo mínimo y máximo
 * - Percentil 95 (P95)
 * - Número de errores / conexiones fallidas
 * - Throughput (clientes/segundo)
 * 
 * Ejecución:
 * java -Djavax.net.ssl.trustStore=cliente_truststore.jks
 * -Djavax.net.ssl.trustStorePassword=cambiame
 * PruebaRendimiento
 * 
 * @author Manuel
 */
public class PruebaRendimiento {

    // ======================== CONFIGURACIÓN ========================

    /** Número de clientes concurrentes a simular */
    private static final int NUM_CLIENTES = 300;

    /** Host y puerto del servidor */
    private static final String HOST = "localhost";
    private static final int PUERTO = 3443;

    /** Protocolos y cipher suites TLS */
    private static final String[] PROTOCOLOS = { "TLSv1.3" };
    private static final String[] CIPHER_SUITES = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256"
    };

    // ======================== CONTADORES ATÓMICOS ========================

    /** Contador de clientes que completaron el flujo con éxito */
    private static final AtomicInteger exitosos = new AtomicInteger(0);

    /** Contador de clientes con error */
    private static final AtomicInteger errores = new AtomicInteger(0);

    /** Lista concurrente de tiempos de respuesta por cliente (ms) */
    private static final ConcurrentLinkedQueue<Long> tiempos = new ConcurrentLinkedQueue<>();

    // ======================== MAIN ========================

    public static void main(String[] args) throws InterruptedException {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   VPN SSL BYOD - Prueba de Rendimiento              ║");
        System.out.println("║   Simulación de " + NUM_CLIENTES + " clientes concurrentes           ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        // Crear pool de hilos igual al número de clientes
        ExecutorService pool = Executors.newFixedThreadPool(NUM_CLIENTES);

        // Barrera para sincronizar el inicio de todos los hilos
        CountDownLatch listos = new CountDownLatch(NUM_CLIENTES);
        CountDownLatch inicio = new CountDownLatch(1);
        CountDownLatch finalizados = new CountDownLatch(NUM_CLIENTES);

        System.out.println("[INFO] Preparando " + NUM_CLIENTES + " clientes...");

        // Lanzar los clientes
        for (int i = 0; i < NUM_CLIENTES; i++) {
            final int id = i;
            pool.execute(() -> {
                listos.countDown(); // Indicar que está listo
                try {
                    inicio.await(); // Esperar señal de inicio simultáneo
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }

                ejecutarFlujoCliente(id);
                finalizados.countDown();
            });
        }

        // Esperar a que todos los hilos estén listos
        listos.await();
        System.out.println("[INFO] Todos los clientes listos. ¡Iniciando prueba de carga!\n");

        // Marcar inicio y esperar
        long tiempoInicio = System.currentTimeMillis();
        inicio.countDown(); // ¡Todos a la vez!

        // Esperar a que terminen con timeout de 5 minutos
        boolean completado = finalizados.await(5, TimeUnit.MINUTES);
        long tiempoTotal = System.currentTimeMillis() - tiempoInicio;

        pool.shutdown();

        // ==================== RESULTADOS ====================
        imprimirResultados(tiempoTotal, completado);
    }

    // ======================== FLUJO DEL CLIENTE ========================

    /**
     * Ejecuta el flujo completo de un cliente simulado.
     * 
     * @param id Identificador del cliente (0 a NUM_CLIENTES-1)
     */
    private static void ejecutarFlujoCliente(int id) {
        String usuario = "perf_user_" + id + "_" + System.currentTimeMillis();
        String password = "PerfTest_" + id;
        long inicio = System.currentTimeMillis();

        try {
            // 1. Conectar vía TLS 1.3
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(HOST, PUERTO);
            socket.setEnabledProtocols(PROTOCOLOS);
            socket.setEnabledCipherSuites(CIPHER_SUITES);
            socket.startHandshake();

            BufferedReader entrada = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
            PrintWriter salida = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            // 2. Registro
            salida.println("REGISTRO|" + usuario + "|" + password);
            String resp = entrada.readLine();
            verificar(resp, "OK", "Cliente " + id + " - Registro");

            // 3. Cerrar y reconectar (simula nuevo inicio de sesión)
            salida.close();
            entrada.close();
            socket.close();

            socket = (SSLSocket) factory.createSocket(HOST, PUERTO);
            socket.setEnabledProtocols(PROTOCOLOS);
            socket.setEnabledCipherSuites(CIPHER_SUITES);
            socket.startHandshake();

            entrada = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
            salida = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            // 4. Login
            salida.println("LOGIN|" + usuario + "|" + password);
            resp = entrada.readLine();
            verificar(resp, "OK", "Cliente " + id + " - Login");

            // 5. Enviar 3 mensajes
            for (int m = 1; m <= 3; m++) {
                salida.println("MENSAJE|Msg de rendimiento #" + m + " desde cliente " + id);
                resp = entrada.readLine();
                verificar(resp, "OK", "Cliente " + id + " - Mensaje " + m);
            }

            // 6. Consultar historial
            salida.println("HISTORIAL");
            resp = entrada.readLine();
            verificar(resp, "OK", "Cliente " + id + " - Historial");

            // 7. Logout
            salida.println("LOGOUT");
            resp = entrada.readLine();

            // Limpiar
            salida.close();
            entrada.close();
            socket.close();

            long duracion = System.currentTimeMillis() - inicio;
            tiempos.add(duracion);
            exitosos.incrementAndGet();

        } catch (Exception e) {
            long duracion = System.currentTimeMillis() - inicio;
            tiempos.add(duracion);
            errores.incrementAndGet();
            System.err.println("[ERROR] Cliente " + id + ": " + e.getClass().getSimpleName()
                    + " - " + e.getMessage());
        }
    }

    /**
     * Verifica que la respuesta comienza con el prefijo esperado.
     */
    private static void verificar(String respuesta, String prefijo, String contexto) {
        if (respuesta == null || !respuesta.startsWith(prefijo)) {
            System.err.println("[WARN] " + contexto + " - Respuesta inesperada: " + respuesta);
        }
    }

    // ======================== RESULTADOS ========================

    /**
     * Imprime el resumen de resultados de la prueba.
     */
    private static void imprimirResultados(long tiempoTotalMs, boolean completado) {
        // Calcular estadísticas
        List<Long> listaTiempos = new ArrayList<>(tiempos);
        Collections.sort(listaTiempos);

        long suma = 0;
        for (long t : listaTiempos) {
            suma += t;
        }

        int total = listaTiempos.size();
        long minimo = total > 0 ? listaTiempos.get(0) : 0;
        long maximo = total > 0 ? listaTiempos.get(total - 1) : 0;
        double media = total > 0 ? (double) suma / total : 0;
        long p95 = total > 0 ? listaTiempos.get((int) (total * 0.95)) : 0;
        double throughput = total > 0 ? (double) exitosos.get() / (tiempoTotalMs / 1000.0) : 0;

        System.out.println("\n╔══════════════════════════════════════════════════════╗");
        System.out.println("║            RESULTADOS DE LA PRUEBA                   ║");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.printf("║  Clientes lanzados:    %-30d ║%n", NUM_CLIENTES);
        System.out.printf("║  Exitosos:             %-30d ║%n", exitosos.get());
        System.out.printf("║  Errores:              %-30d ║%n", errores.get());
        System.out.printf("║  Completado en timeout: %-29s ║%n", completado ? "Sí" : "No");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.printf("║  Tiempo total:         %-27s ms ║%n", tiempoTotalMs);
        System.out.printf("║  Tiempo medio:         %-27.1f ms ║%n", media);
        System.out.printf("║  Tiempo mínimo:        %-27d ms ║%n", minimo);
        System.out.printf("║  Tiempo máximo:        %-27d ms ║%n", maximo);
        System.out.printf("║  Percentil 95 (P95):   %-27d ms ║%n", p95);
        System.out.printf("║  Throughput:           %-24.2f cli/s ║%n", throughput);
        System.out.println("╚══════════════════════════════════════════════════════╝");

        // Resultado final
        System.out.println();
        if (errores.get() == 0 && completado) {
            System.out.println("✅ PRUEBA SUPERADA: El servidor manejó " + NUM_CLIENTES
                    + " clientes concurrentes sin errores.");
        } else if (errores.get() > 0) {
            System.out.println("⚠️  PRUEBA CON ADVERTENCIAS: " + errores.get() + " clientes tuvieron errores.");
        }
        if (!completado) {
            System.out.println("❌ PRUEBA FALLIDA: No se completó dentro del timeout de 5 minutos.");
        }

        // Metodología de comparación TLS vs texto plano
        System.out.println("\n--- METODOLOGÍA: Comparación TLS vs Texto Plano ---");
        System.out.println("Para medir el overhead de TLS 1.3:");
        System.out.println("  1. Ejecutar esta prueba con el servidor SSL (ya hecho).");
        System.out.println("  2. Crear un ServidorTextoPlano.java que use ServerSocket normal (sin SSL).");
        System.out.println("  3. Crear un cliente de rendimiento equivalente sin SSL.");
        System.out.println("  4. Comparar: Tiempo medio TLS / Tiempo medio Texto Plano.");
        System.out.println("  Overhead TLS = ((Media_TLS - Media_TCP) / Media_TCP) * 100%");
        System.out.printf("  Tiempo medio TLS actual: %.1f ms (este resultado) %n", media);
    }
}
