#!/usr/bin/env python3
"""
PruebaMitM.py

Prueba de concepto (PoC) de ataque Man-in-the-Middle (MitM) contra la VPN SSL BYOD.

Este script:
  1. Genera un certificado SSL autofirmado FALSO (diferente al del servidor real).
  2. Levanta un proxy TLS en un puerto intermedio (4443).
  3. Cuando el cliente Java intenta conectar al proxy, el handshake TLS FALLA
     porque el truststore del cliente solo confía en el certificado del servidor real.
  4. Demuestra que la configuración estricta del TrustStore mitiga ataques MitM.

Uso:
  1. Asegurar que el servidor real está corriendo en puerto 3443.
  2. Ejecutar este script:
       python PruebaMitM.py
  3. En otra terminal, intentar conectar el cliente al proxy (puerto 4443):
       java -Djavax.net.ssl.trustStore=cliente_truststore.jks 
            -Djavax.net.ssl.trustStorePassword=cambiame 
            -Djavax.net.ssl.host=localhost 
            ClienteSSL
     (Modificar temporalmente ClienteSSL.java para conectar al puerto 4443,
      o usar la versión de test que acepta el puerto por parámetro.)

Resultado esperado:
  - El cliente Java lanzará javax.net.ssl.SSLHandshakeException
  - El proxy MitM NO podrá interceptar la comunicación
  - Esto demuestra que TLS 1.3 + TrustStore previene MitM

Requisitos:
  - Python 3.6+
  - No se necesitan dependencias externas

@author Manuel
"""

import ssl
import socket
import threading
import subprocess
import os
import sys
import time
import tempfile

# ======================== CONFIGURACIÓN ========================

PUERTO_PROXY = 4443            # Puerto donde escucha el proxy MitM
SERVIDOR_REAL_HOST = "localhost"
SERVIDOR_REAL_PUERTO = 3443    # Puerto del servidor SSL real
CERT_FALSO = "mitm_cert.pem"   # Certificado falso generado
KEY_FALSA = "mitm_key.pem"     # Clave privada falsa generada


def generar_certificado_falso():
    """
    Genera un certificado SSL autofirmado FALSO para el proxy MitM.
    Usa el módulo ssl de Python para generar un par clave/certificado.
    El CN será 'localhost' para intentar engañar al cliente,
    pero el certificado NO estará en el truststore del cliente Java.
    """
    print("[MitM] Generando certificado falso autofirmado...")
    
    # Usar openssl para generar el certificado (disponible en la mayoría de sistemas)
    try:
        # Generar clave privada RSA 2048
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FALSA,
            "-out", CERT_FALSO,
            "-days", "1",
            "-nodes",  # Sin contraseña en la clave
            "-subj", "/CN=localhost/O=MitM_Atacante/C=XX"
        ], check=True, capture_output=True, text=True)
        
        print(f"[MitM] Certificado falso generado: {CERT_FALSO}")
        print(f"[MitM] Clave falsa generada: {KEY_FALSA}")
        print(f"[MitM] CN=localhost, O=MitM_Atacante (NO coincide con el truststore del cliente)")
        return True
        
    except FileNotFoundError:
        print("[ERROR] OpenSSL no encontrado. Intentando método alternativo con keytool...")
        return generar_certificado_con_keytool()
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error generando certificado: {e.stderr}")
        return False


def generar_certificado_con_keytool():
    """
    Método alternativo usando keytool de Java para generar certificado falso.
    """
    try:
        # Generar keystore falso
        subprocess.run([
            "keytool", "-genkeypair",
            "-alias", "mitm",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "1",
            "-keystore", "mitm_keystore.jks",
            "-storepass", "atacante",
            "-dname", "CN=localhost, OU=MitM, O=Atacante, C=XX"
        ], check=True, capture_output=True, text=True)
        
        # Exportar a PEM (necesita openssl, así que simplemente usamos el JKS directamente)
        print("[MitM] Keystore MitM generado: mitm_keystore.jks")
        return True
        
    except Exception as e:
        print(f"[ERROR] No se pudo generar certificado: {e}")
        return False


def proxy_mitm():
    """
    Levanta un servidor TLS proxy que intenta interceptar la comunicación.
    
    Funcionamiento:
    1. El proxy acepta conexiones TLS en PUERTO_PROXY con su certificado FALSO.
    2. Si un cliente acepta el certificado falso (MAL CONFIGURADO), el proxy
       reenvía el tráfico al servidor real en SERVIDOR_REAL_PUERTO.
    3. Si el cliente RECHAZA el certificado (bien configurado con TrustStore),
       el handshake falla y la conexión se cierra. Esto es lo ESPERADO.
    """
    print(f"\n[MitM] ═══════════════════════════════════════════════════")
    print(f"[MitM]   PROXY MAN-IN-THE-MIDDLE INICIADO")
    print(f"[MitM]   Escuchando en puerto {PUERTO_PROXY}")
    print(f"[MitM]   Servidor real en {SERVIDOR_REAL_HOST}:{SERVIDOR_REAL_PUERTO}")
    print(f"[MitM] ═══════════════════════════════════════════════════\n")
    
    # Crear contexto SSL con certificado falso
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    try:
        contexto.load_cert_chain(certfile=CERT_FALSO, keyfile=KEY_FALSA)
    except Exception as e:
        print(f"[ERROR] No se pudo cargar el certificado falso: {e}")
        return
    
    # Permitir TLS 1.3
    contexto.minimum_version = ssl.TLSVersion.TLSv1_3
    
    # Crear socket servidor
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("0.0.0.0", PUERTO_PROXY))
    servidor.listen(5)
    
    print(f"[MitM] Esperando conexiones de víctimas en puerto {PUERTO_PROXY}...")
    print(f"[MitM] Para probar, ejecute el cliente Java apuntando al puerto {PUERTO_PROXY}:\n")
    print(f"  Modifique HOST/PUERTO en ClienteSSL.java o ejecute:")
    print(f"    java -Djavax.net.ssl.trustStore=cliente_truststore.jks \\")
    print(f"         -Djavax.net.ssl.trustStorePassword=cambiame \\")
    print(f"         ClienteSSLMitM\n")
    
    intentos = 0
    while True:
        try:
            conn_raw, addr = servidor.accept()
            intentos += 1
            print(f"\n[MitM] ¡Conexión entrante #{intentos} desde {addr[0]}:{addr[1]}!")
            print(f"[MitM] Intentando handshake TLS con certificado FALSO...")
            
            try:
                conn_ssl = contexto.wrap_socket(conn_raw, server_side=True)
                
                # Si llegamos aquí, el cliente ACEPTÓ el certificado falso (MAL)
                print(f"[MitM] ⚠️  ¡ALERTA! El cliente ACEPTÓ el certificado falso.")
                print(f"[MitM] Esto significa que el TrustStore NO está configurado correctamente.")
                print(f"[MitM] Interceptando tráfico...")
                
                # Leer datos del cliente
                datos = conn_ssl.recv(4096)
                print(f"[MitM] Datos interceptados: {datos.decode('utf-8', errors='replace')}")
                
                conn_ssl.close()
                
            except ssl.SSLError as e:
                print(f"[MitM] ✅ Handshake FALLIDO (esperado): {e}")
                print(f"[MitM] ✅ El cliente Java RECHAZÓ el certificado falso.")
                print(f"[MitM] ✅ ¡El TrustStore protege contra este ataque MitM!")
                
            except ConnectionResetError:
                print(f"[MitM] ✅ Conexión reseteada por el cliente (rechazó el cert).")
                print(f"[MitM] ✅ ¡Protección MitM funcionando correctamente!")
                
            except Exception as e:
                print(f"[MitM] Error en la conexión: {type(e).__name__}: {e}")
                
        except KeyboardInterrupt:
            print("\n[MitM] Proxy detenido por el usuario.")
            break
    
    servidor.close()
    limpiar_archivos()


def limpiar_archivos():
    """Elimina los archivos temporales del certificado falso."""
    for archivo in [CERT_FALSO, KEY_FALSA]:
        if os.path.exists(archivo):
            os.remove(archivo)
            print(f"[MitM] Eliminado: {archivo}")


def crear_cliente_test_mitm():
    """
    Genera un fichero Java auxiliar (ClienteSSLMitM.java) que conecta
    al puerto del proxy MitM (4443) en lugar del servidor real.
    Esto permite probar el ataque sin modificar ClienteSSL.java.
    """
    codigo = '''import java.io.*;
import javax.net.ssl.*;

/**
 * ClienteSSLMitM.java
 * 
 * Cliente auxiliar que intenta conectar al proxy MitM (puerto 4443).
 * Se espera que el handshake TLS FALLE porque el certificado del proxy
 * no está en el truststore del cliente.
 * 
 * Ejecución:
 *   java -Djavax.net.ssl.trustStore=cliente_truststore.jks 
 *        -Djavax.net.ssl.trustStorePassword=cambiame 
 *        ClienteSSLMitM
 */
public class ClienteSSLMitM {
    public static void main(String[] args) {
        System.out.println("=== Prueba MitM: Conectando al proxy atacante (puerto 4443) ===\\n");
        
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 4443);
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            
            System.out.println("Intentando handshake TLS con el proxy MitM...");
            socket.startHandshake();
            
            // Si llegamos aquí, algo va MAL
            System.out.println("⚠️  ALERTA: El handshake fue exitoso con el proxy atacante.");
            System.out.println("El TrustStore NO está protegiendo correctamente.");
            socket.close();
            
        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.out.println("✅ SSLHandshakeException capturada correctamente.");
            System.out.println("✅ El cliente RECHAZÓ el certificado falso del atacante.");
            System.out.println("✅ El TrustStore protege contra el ataque MitM.");
            System.out.println("\\nDetalle de la excepción:");
            System.out.println("  " + e.getMessage());
            
        } catch (Exception e) {
            System.out.println("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
'''
    
    with open("ClienteSSLMitM.java", "w", encoding="utf-8") as f:
        f.write(codigo)
    
    print(f"[MitM] Archivo auxiliar generado: ClienteSSLMitM.java")
    print(f"[MitM] Compílelo con: javac ClienteSSLMitM.java")


# ======================== MAIN ========================

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════╗")
    print("║   VPN SSL BYOD - Prueba de Concepto MitM            ║")
    print("║   Man-in-the-Middle Attack Simulation               ║")
    print("╚══════════════════════════════════════════════════════╝\n")
    
    print("OBJETIVO: Demostrar que TLS 1.3 + TrustStore previene")
    print("la interceptación de tráfico por un atacante.\n")
    
    # Paso 1: Generar certificado falso
    if not generar_certificado_falso():
        print("[ERROR] No se pudo generar el certificado MitM. Abortando.")
        sys.exit(1)
    
    # Paso 2: Generar cliente auxiliar de test
    crear_cliente_test_mitm()
    
    # Paso 3: Iniciar proxy MitM
    print("\n" + "="*60)
    print("INSTRUCCIONES:")
    print("  1. Deje este script corriendo (es el proxy MitM).")
    print("  2. En OTRA terminal, compile y ejecute el cliente MitM:")
    print(f"     javac ClienteSSLMitM.java")
    print(f"     java -Djavax.net.ssl.trustStore=cliente_truststore.jks \\")
    print(f"          -Djavax.net.ssl.trustStorePassword=cambiame ClienteSSLMitM")
    print("  3. Observe cómo el cliente RECHAZA la conexión.")
    print("  4. Presione Ctrl+C para detener el proxy.")
    print("="*60 + "\n")
    
    proxy_mitm()
