import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * PruebaRendimientoSinSSL.java
 * 
 * Simulación de carga de 300 clientes concurrentes contra el servidor SIN SSL.
 * Usa sockets TCP planos (sin cifrado) para comparar rendimiento con la
 * versión TLS y calcular el overhead de TLS 1.3.
 * 
 * Cada cliente ejecuta un flujo completo:
 * 1. Conexión TCP plana
 * 2. Registro (usuario único por hilo)
 * 3. Login
 * 4. Enviar 3 mensajes
 * 5. Consultar historial
 * 6. Logout
 * 
 * Ejecución:
 * java -cp "classes;sqlite-jdbc-3.47.2.0.jar" PruebaRendimientoSinSSL
 * 
 * @author Manuel
 */
public class PruebaRendimientoSinSSL {

    // ======================== CONFIGURACIÓN ========================

    /** Número de clientes concurrentes a simular */
    private static final int NUM_CLIENTES = 300;

    /** Host y puerto del servidor sin SSL */
    private static final String HOST = "localhost";
    private static final int PUERTO = 3080;

    // ======================== CONTADORES ATÓMICOS ========================

    private static final AtomicInteger exitosos = new AtomicInteger(0);
    private static final AtomicInteger errores = new AtomicInteger(0);
    private static final ConcurrentLinkedQueue<Long> tiempos = new ConcurrentLinkedQueue<>();

    // ======================== MAIN ========================

    public static void main(String[] args) throws InterruptedException {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║   VPN BYOD - Prueba de Rendimiento SIN SSL          ║");
        System.out.println("║   Simulación de " + NUM_CLIENTES + " clientes concurrentes           ║");
        System.out.println("║   (TCP plano, sin cifrado - benchmark)               ║");
        System.out.println("╚══════════════════════════════════════════════════════╝\n");

        ExecutorService pool = Executors.newFixedThreadPool(NUM_CLIENTES);

        CountDownLatch listos = new CountDownLatch(NUM_CLIENTES);
        CountDownLatch inicio = new CountDownLatch(1);
        CountDownLatch finalizados = new CountDownLatch(NUM_CLIENTES);

        System.out.println("[INFO] Preparando " + NUM_CLIENTES + " clientes...");

        for (int i = 0; i < NUM_CLIENTES; i++) {
            final int id = i;
            pool.execute(() -> {
                listos.countDown();
                try {
                    inicio.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }

                ejecutarFlujoCliente(id);
                finalizados.countDown();
            });
        }

        listos.await();
        System.out.println("[INFO] Todos los clientes listos. ¡Iniciando prueba de carga!\n");

        long tiempoInicio = System.currentTimeMillis();
        inicio.countDown();

        boolean completado = finalizados.await(5, TimeUnit.MINUTES);
        long tiempoTotal = System.currentTimeMillis() - tiempoInicio;

        pool.shutdown();

        imprimirResultados(tiempoTotal, completado);
        guardarLog(tiempoTotal, completado);
    }

    // ======================== FLUJO DEL CLIENTE ========================

    private static void ejecutarFlujoCliente(int id) {
        String usuario = "perf_nossl_" + id + "_" + System.currentTimeMillis();
        String password = "PerfTest_" + id;
        long inicio = System.currentTimeMillis();

        try {
            // 1. Conectar vía TCP plano (con reintentos)
            Socket socket = null;
            int maxReintentos = 5;
            for (int intento = 0; intento < maxReintentos; intento++) {
                try {
                    socket = new Socket(HOST, PUERTO);
                    break;
                } catch (java.net.ConnectException e) {
                    if (intento == maxReintentos - 1) throw e;
                    Thread.sleep(100 + (long)(Math.random() * 200));
                }
            }

            BufferedReader entrada = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
            PrintWriter salida = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            // 2. Registro
            salida.println("REGISTRO|" + usuario + "|" + password);
            String resp = entrada.readLine();
            verificar(resp, "OK", "Cliente " + id + " - Registro");

            // 3. Cerrar y reconectar
            salida.close();
            entrada.close();
            socket.close();

            for (int intento = 0; intento < maxReintentos; intento++) {
                try {
                    socket = new Socket(HOST, PUERTO);
                    break;
                } catch (java.net.ConnectException e) {
                    if (intento == maxReintentos - 1) throw e;
                    Thread.sleep(100 + (long)(Math.random() * 200));
                }
            }

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

    private static void verificar(String respuesta, String prefijo, String contexto) {
        if (respuesta == null || !respuesta.startsWith(prefijo)) {
            System.err.println("[WARN] " + contexto + " - Respuesta inesperada: " + respuesta);
        }
    }

    // ======================== RESULTADOS ========================

    private static void imprimirResultados(long tiempoTotalMs, boolean completado) {
        List<Long> listaTiempos = new ArrayList<>(tiempos);
        Collections.sort(listaTiempos);

        long suma = 0;
        for (long t : listaTiempos) suma += t;

        int total = listaTiempos.size();
        long minimo = total > 0 ? listaTiempos.get(0) : 0;
        long maximo = total > 0 ? listaTiempos.get(total - 1) : 0;
        double media = total > 0 ? (double) suma / total : 0;
        long p95 = total > 0 ? listaTiempos.get((int) (total * 0.95)) : 0;
        double throughput = total > 0 ? (double) exitosos.get() / (tiempoTotalMs / 1000.0) : 0;

        System.out.println("\n╔══════════════════════════════════════════════════════╗");
        System.out.println("║       RESULTADOS - RENDIMIENTO SIN SSL               ║");
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

        System.out.println();
        if (errores.get() == 0 && completado) {
            System.out.println(" PRUEBA SUPERADA: El servidor manejó " + NUM_CLIENTES
                    + " clientes concurrentes sin errores.");
        } else if (errores.get() > 0) {
            System.out.println(" PRUEBA CON ADVERTENCIAS: " + errores.get() + " clientes tuvieron errores.");
        }
        if (!completado) {
            System.out.println(" PRUEBA FALLIDA: No se completó dentro del timeout de 5 minutos.");
        }

        System.out.printf("  Tiempo medio TCP plano: %.1f ms (este resultado) %n", media);
    }

    // ======================== LOG ========================

    private static void guardarLog(long tiempoTotalMs, boolean completado) {
        try {
            new File("logs").mkdirs();

            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            String nombreArchivo = "logs/PruebaRendimientoSinSSL_" + timestamp + ".log";

            List<Long> listaTiempos = new ArrayList<>(tiempos);
            Collections.sort(listaTiempos);

            long suma = 0;
            for (long t : listaTiempos) suma += t;

            int total = listaTiempos.size();
            long minimo = total > 0 ? listaTiempos.get(0) : 0;
            long maximo = total > 0 ? listaTiempos.get(total - 1) : 0;
            double media = total > 0 ? (double) suma / total : 0;
            long p95 = total > 0 ? listaTiempos.get((int) (total * 0.95)) : 0;
            double throughput = total > 0 ? (double) exitosos.get() / (tiempoTotalMs / 1000.0) : 0;

            try (PrintWriter log = new PrintWriter(new FileWriter(nombreArchivo))) {
                log.println("========================================");
                log.println("  TEST: PruebaRendimientoSinSSL");
                log.println("  FECHA: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                log.println("  MODO: TCP plano (sin cifrado)");
                log.println("========================================");
                log.println();
                log.println("RESULTADOS DE LA PRUEBA DE RENDIMIENTO (SIN SSL)");
                log.println("------------------------------------------------");
                log.printf("Clientes lanzados:     %d%n", NUM_CLIENTES);
                log.printf("Exitosos:              %d%n", exitosos.get());
                log.printf("Errores:               %d%n", errores.get());
                log.printf("Completado en timeout: %s%n", completado ? "Sí" : "No");
                log.println();
                log.printf("Tiempo total:          %d ms%n", tiempoTotalMs);
                log.printf("Tiempo medio:          %.1f ms%n", media);
                log.printf("Tiempo mínimo:         %d ms%n", minimo);
                log.printf("Tiempo máximo:         %d ms%n", maximo);
                log.printf("Percentil 95 (P95):    %d ms%n", p95);
                log.printf("Throughput:            %.2f cli/s%n", throughput);
                log.println();
                if (errores.get() == 0 && completado) {
                    log.println("RESULTADO: PRUEBA SUPERADA");
                } else if (errores.get() > 0) {
                    log.println("RESULTADO: PRUEBA CON ADVERTENCIAS (" + errores.get() + " errores)");
                }
                if (!completado) {
                    log.println("RESULTADO: PRUEBA FALLIDA (timeout)");
                }
            }

            System.out.println("\n[LOG] Resultados guardados en: " + nombreArchivo);
        } catch (IOException e) {
            System.err.println("[LOG] Error al guardar log: " + e.getMessage());
        }
    }
}
