# Validador de Credenciales SSH/Telnet

Herramienta para validación de credenciales SSH y Telnet utilizando Shodan API.

## ADVERTENCIA

**Esta herramienta es EXCLUSIVAMENTE para fines académicos y éticos.**

El uso indebido de esta herramienta puede tener consecuencias legales graves. El usuario asume toda la responsabilidad legal por cualquier uso indebido.

## Descripción

Esta aplicación permite realizar auditorías y validaciones de credenciales SSH y Telnet utilizando Shodan API para identificar servicios expuestos en países de Latinoamérica. Desarrollada como parte de un ejercicio académico de seguridad informática aplicada.

## Funcionalidades

### Funcionalidades Básicas
- Búsqueda en Shodan API para identificar IPs con servicios SSH (puerto 22) y Telnet (puerto 23) expuestos en países de Latinoamérica
- Detección de servicios SSH/Telnet en puertos no convencionales
- Gestión y carga de listas independientes de IPs, usuarios y contraseñas desde archivos .txt
- Validación efectiva de la apertura de puertos mediante conexiones reales

### Funcionalidades Avanzadas
- Automatización de validación masiva de credenciales mediante SSH (paramiko) y Telnet (telnetlib)
- Generación de reportes estadísticos del total y porcentaje de IPs accesibles
- Implementación de manejo robusto de errores (autenticación fallida, conexión fallida, timeout, etc.)
- Generación automática de logs y archivos con credenciales válidas encontradas
- Uso de múltiples claves API de Shodan para optimizar los límites de búsqueda
- Paralelización mediante hilos para mejorar el rendimiento

## Requisitos

- Python 3.x
- Kali Linux (preferentemente) o Windows 11 con Python instalado
- Bibliotecas Python:
  - paramiko (SSH)
  - telnetlib (incluida en la biblioteca estándar de Python)
  - shodan
  - otros módulos estándar

## Instalación

1. Clonar o descargar este repositorio:
   ```
   git clone <URL-del-repositorio>
   ```

2. Instalar las dependencias:
   ```
   pip install -r requirements.txt
   ```
   
   Contenido del archivo requirements.txt:
   ```
   shodan>=1.28.0
   paramiko>=2.12.0
   ```

3. Configurar su(s) clave(s) API de Shodan en un archivo de texto (una por línea)

## Uso

### Estructura de archivos

Debe crear los siguientes archivos:
- `api_keys.txt`: Una o más claves API de Shodan (una por línea)
- `users.txt`: Lista de usuarios a probar (uno por línea)
- `passwords.txt`: Lista de contraseñas a probar (una por línea)
- (Opcional) `ips.txt`: Lista de IPs a probar si no desea usar Shodan

### Comando básico

```
python validator.py -k api_keys.txt -u users.txt -p passwords.txt
```

### Opciones disponibles

```
  -h, --help            Muestra este mensaje de ayuda
  -k API_KEYS, --api-keys API_KEYS
                        Archivo con claves API de Shodan (una por línea)
  -i IPS, --ips IPS     Archivo con lista de IPs (opcional, si no se proporciona se usará Shodan)
  -u USERS, --users USERS
                        Archivo con lista de usuarios
  -p PASSWORDS, --passwords PASSWORDS
                        Archivo con lista de contraseñas
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directorio para guardar resultados (default: results)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout para conexiones (default: 5s)
  -c COUNTRIES [COUNTRIES ...], --countries COUNTRIES [COUNTRIES ...]
                        Códigos de países a buscar (default: Latinoamérica)
  -m MAX_THREADS, --max-threads MAX_THREADS
                        Número máximo de hilos concurrentes (default: 10)
  -s {ssh,telnet,both}, --service {ssh,telnet,both}
                        Servicio a probar (ssh, telnet o both)
```

### Ejemplos de uso

1. Buscar servicios SSH y Telnet en Latinoamérica y probar credenciales:
   ```
   python validator.py -k api_keys.txt -u users.txt -p passwords.txt
   ```

2. Probar servicios SSH en IPs de un archivo:
   ```
   python validator.py -k api_keys.txt -i ips.txt -u users.txt -p passwords.txt -s ssh
   ```

3. Buscar servicios Telnet solo en México con timeout más largo:
   ```
   python validator.py -k api_keys.txt -u users.txt -p passwords.txt -s telnet -c MX -t 10
   ```

4. Aumentar el número de hilos para mejorar rendimiento:
   ```
   python validator.py -k api_keys.txt -u users.txt -p passwords.txt -m 20
   ```

## Limitaciones y consideraciones

### Créditos de Shodan API

- La API gratuita de Shodan tiene límites en la cantidad de resultados que puede devolver.
- Se recomienda utilizar múltiples claves API para evitar alcanzar estos límites.
- Considere adquirir créditos adicionales para búsquedas más extensas.
- El script rota automáticamente entre las claves disponibles cuando se alcanza un límite.

### Rendimiento

- El escaneo de múltiples objetivos puede tomar mucho tiempo, especialmente con listas grandes de usuarios y contraseñas.
- Se recomienda empezar con listas pequeñas para probar el funcionamiento.
- La herramienta utiliza paralelización mediante hilos para mejorar el rendimiento.
- Ajuste el parámetro `-m/--max-threads` según la capacidad de su sistema.

### Consideraciones legales

- Solo utilice esta herramienta en sistemas para los que tenga autorización explícita.
- El escaneo no autorizado puede ser ilegal en muchas jurisdicciones.
- Esta herramienta es exclusivamente para fines académicos y educativos.

## Estructura del proyecto

- `validator.py`: Script principal
- `results/`: Directorio donde se guardan los resultados de las ejecuciones
  - `shodan_results_*.json`: Resultados de la búsqueda en Shodan
  - `valid_credentials_*.csv`: Credenciales válidas encontradas
  - `detailed_results_*.json`: Resultados detallados de cada objetivo
  - `report_*.txt`: Reporte estadístico
- `validator.log`: Archivo de registro detallado

## Salida

La herramienta genera los siguientes archivos de salida:
- Resultados de búsqueda de Shodan (JSON)
- Reporte estadístico (TXT)
- Lista de credenciales válidas encontradas (CSV)
- Resultados detallados de cada objetivo (JSON)
- Logs detallados (LOG)

## Documentación del uso de IA para este proyecto

Este script fue generado con la asistencia de Claude, una IA de Anthropic. Los prompts utilizados se centraron en los requisitos específicos del proyecto académico, enfatizando las funcionalidades básicas y avanzadas solicitadas.

### Prompts utilizados:

1. Prompt inicial para establecer el contexto: "Recuerda que eres un experto en ciberseguridad, para que me ayudes a crear un script en python que tenga los siguientes requerimientos..." seguido de la descripción detallada del proyecto.

2. Solicitud de estructuración modular: Se pidió específicamente que el código siguiera un enfoque modular y bien estructurado para facilitar su comprensión y mantenimiento.

3. Énfasis en el manejo de errores: Se solicitó especial atención al manejo robusto de errores, incluyendo problemas de conexión, autenticación fallida, y límites de la API.

4. Documentación: Se requirió documentación detallada tanto dentro del código como en el README.

La IA ayudó a generar la estructura básica y funcionalidades principales, mientras que la integración con Shodan API y refinamientos específicos fueron implementados manualmente.

## Autor

[Tu Nombre]

## Fecha

5 de abril de 2025

## Licencia

Este proyecto es exclusivamente para fines académicos y no se proporciona bajo ninguna licencia de uso comercial.
