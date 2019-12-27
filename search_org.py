#!/usr/bin/env python3

""" Modulos que se necesitan"""
import shodan
import dnspython
import argparse
import nmap



""" Argumentos solicitados"""
def argumentos():
    parser = argparse.ArgumentParser()
    parser.add_argument("dominio",
                        type=str,
                        help='Digite el dominio que se analiza')
    args = parser.parse_args()
    return args


def dnsdata(dominio):
    ips = []
    """ Extraer los MX del dominio"""
    try:
        print("--------------------------------------------------------------")
        print("\t\t\tServicios de correo detectados \n ")
        for mx in dns.resolver.query(dominio, 'MX'):
            print('\t[!] ' + str(mx.exchange))
    except:
        print("\n\n El dominio no tiene registros MX")

    try:
        print("\n\n")
        print("--------------------------------------------------------------")
        print("\t\t\tRegistos de seguridad de correo\n")
        for txt in dns.resolver.query(dominio, 'TXT'):
            print('\t[!] ' + str(txt))
    except:
        print("\n\t [*] No tiene registros de seguridad para correo")

    """ Extraer IPs """

    names = ["", "sinergy.", "www.", "mail.", "mail2.", "correo.", "webmail.", "vpn.", "sip.", "smtp.", "pop.", "pop3.", "imap."]
    for server in names:
        try:
            for ip in dns.resolver.query(server + dominio, 'A'):
                ips.append(str(ip))
        except:
            pass
    return (ips)

def infonmap(ips):
    print('\n\n')
    print("--------------------------------------------------------------")
    print("\t\t\tInformación de las IPS \n")

    for ip in set(ips):
        nm = nmap.PortScanner()
        nm.scan(hosts=ip,arguments='-sV -T4 -Pn -p 21,22,25,80,443,445,993,3389,8080,8443')
        for port in nm[ip]['tcp'].keys():
            if nm[ip]['tcp'][port]['state'] == 'open':
                print('\t[*] Detectado un servicio en la IP ' + ip + ' en puerto ' + str(port))
                print('\t\t[!] Servicio : ' + nm[ip]['tcp'][port]['name'])
                print('\t\t[!] Software : ' + nm[ip]['tcp'][port]['product'])
                print('\t\t[!] Version : ' + nm[ip]['tcp'][port]['version'])


def search_org(api_shodan, ips, args):
    """Lista de atributos que se resumiran por org"""
    FACETS = [
        ('port', 10),
        ('os', 10),
        ('vuln', 10),
        ('domain', 10),
        ('ssl.version', 10),
    ]

    FACET_TITLES = {
        'port': 'Top 10 Puertos',
        'os': 'Top 10 Operations Systems',
        'vuln': 'Top 10 Vulnerabilidades',
        'domain': 'Top 10 dominios',
        'ssl.version': 'Top 10 versiones SSL',
    }
    api = shodan.Shodan(api_shodan)
    for ip in ips:
        try:
            info = api.host(ip)
            if len(info['vulns']) >= 1:
                print("\n\n")
                print(
                "--------------------------------------------------------------")
                print(
                    '\t[*] Detectadas vulnerabilidad en la IP ' + ip )
                for vuln in info['vulns']:
                    print('\t\t[!] Vulnerabilidad : ' + vuln)

        except Exception:
            continue

    try:

        args = args.split('.')[0]
        query = 'org:"' + args + '"'
        result = api.count(query, facets=FACETS)
        print("\n\n")
        print("--------------------------------------------------------------")
        print("\t\t\tRegistos de la organizacion   \n")
        print('\t[!] Busqueda: %s' % query)
        print('\t[!] Total detecciones: %s\n' % result['total'])

        """Mostrar los resultados por facetas"""
        if result['total'] == 0:
            print('\t[*] El dominio no se detecta en ninguna organización')
        else:
            for facet in result['facets']:
                print('\t[*] ' + FACET_TITLES[facet])
                for term in result['facets'][facet]:
                    print('\t\t[!] %s: %s' % (term['value'], term['count']))

    except Exception as e:
        print('Error: %s' % e)


def main():
    """ Se configura la llave de la API de Shodan"""
    api_shodan = ""
    args = argumentos()
    if args.dominio == None:
        print(parser.print_usage)
        exit(0)
    else:
        ips = dnsdata(args.dominio)
        infonmap(ips)
        search_org(api_shodan, ips, args.dominio)


if __name__ == '__main__':
    main()
