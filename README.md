# SearchOrg
Colocando el dominio de correo electrónico de una empresa se obtiene información usando el DNS, NMAP y Shodan

# Tener en cuenta

Se debe tener una cuenta con Shodan y cargar el APIKey donde lo indica el script

Configurar las librerias que se requieren y estan en el requirements.txt

# Ejecucion y resultado

dsespitia@castleward:~/script$ python3 search_org.py 11paths.com
--------------------------------------------------------------
      Servicios de correo detectados 
 
  [!] 11paths-com.mail.protection.outlook.com.


--------------------------------------------------------------
      Registos de seguridad de correo

  [!] "v=spf1 include:spf.protection.outlook.com -all"
  [!] "MS=ms48494414"


--------------------------------------------------------------
      Información de las IPS        
  [*] Detectado un servicio en la IP 2.139.155.203 en puerto 80
    [!] Servicio : http
    [!] Software : nginx
    [!] Version :
  [*] Detectado un servicio en la IP 2.139.155.203 en puerto 443
    [!] Servicio : https
    [!] Software : 
    [!] Version : 
  [*] Detectado un servicio en la IP 52.109.12.84 en puerto 80
    [!] Servicio : http
    [!] Software : 
    [!] Version : 
  [*] Detectado un servicio en la IP 52.109.12.84 en puerto 443
    [!] Servicio : ssl
    [!] Software : 
    [!] Version : 


--------------------------------------------------------------
      Registos de la organizacion   

  [!] Busqueda: org:"Telefonica de Espana Static IP"
  [!] Total detecciones: 371368

  [!] Top 10 Vulnerabilidades
    cve-2018-1312: 5415
    cve-2017-7679: 4610
    cve-2019-0220: 4278
    cve-2016-8612: 4246
    cve-2017-15906: 4148
    cve-2018-17199: 4069
    cve-2016-4975: 3672
    cve-2018-1283: 3514
    cve-2017-15715: 3224
    cve-2017-15710: 2942

  [!] Top 10 dominios
    rima-tde.net: 363551
    tecnosis.net: 29
    tarnos.com: 21
    wetron.es: 11
    sortes.com: 9
    tikitaka.es: 8
    grupoballesteros.es: 7
    workpinion.com: 6
    servtelecom.com: 6
    lener.es: 6

  [!] Top 10 Operations Systems
    Linux 3.x: 601
    Windows 6.1: 381
    Linux 2.6.x: 370
    Playstation 4: 367
    Windows 7 or 8: 328
    Unix: 186
    Windows XP: 176
    Windows 7 Professional 7601 Service Pack 1: 56
    Windows Server 2012 R2 Standard 9600: 40
    Linux 2.4-2.6: 36

  [!] Top 10 Puertos
    53: 35149
    80: 34928
    7547: 34267
    443: 26536
    22: 20392
    37777: 15939
    8080: 13905
    1723: 12394
    554: 12227
    9000: 6128

  [!] Top 10 versiones SSL
    tlsv1.2: 42898
    tlsv1.1: 37631
    tlsv1: 35854
    sslv3: 10129
    sslv2: 2065
    tlsv1.3: 993
