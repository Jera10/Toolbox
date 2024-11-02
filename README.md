# Verktygslåda för Penetrationstester och IT-säkerhet

Välkommen till Verktygslådan för Penetrationstester och IT-säkerhet! Denna verktygslåda innehåller tre verktyg som kan användas för att utföra olika uppgifter inom IT-säkerhet och nätverksanalys.
---

## Beskrivning

Denna verktygslåda innehåller följande tre verktyg:

1. **Krypteringsverktyg** - Kryptera och dekryptera filer med hjälp av en symmetrisk nyckel och `cryptography`-biblioteket.
2. **Nätverksskanner** - Skanna nätverk och upptäck öppna portar med hjälp av Nmap genom `python-nmap`-biblioteket.
3. **Packet Sniffer** - Sniffa och analysera nätverkstrafik med hjälp av `scapy`.

Dessa verktyg är utvecklade för utbildningsändamål inom IT-säkerhet och nätverksanalys.

## Förutsättningar

- **Operativsystem:** Windows eller Linux
- **Python:** Version 3.x

### Nödvändiga Python-paket

Installera nödvändiga paket genom att köra följande kommando:

```
pip install -r requirements.txt

```
### Verktygsbeskrivning
1. Krypteringsverktyg
Beskrivning:

Ett verktyg för att kryptera och dekryptera filer med hjälp av en symmetrisk nyckel och cryptography-biblioteket. Detta verktyg kan användas för att säkra känslig information genom att kryptera filer så att endast personer med rätt nyckel kan dekryptera och läsa dem.

Filer:

encrypt_tool.py - Huvudskriptet för kryptering och dekryptering.
generate_key.py - Skript för att generera en ny krypteringsnyckel.

Användning:

Generera en nyckel
Innan du kan kryptera eller dekryptera filer behöver du en nyckel.

```
python generate_key.py
```

En fil key.key kommer att skapas i aktuell katalog.
Notera: Förvara nyckeln säkert; utan den kan du inte dekryptera dina filer.

Kryptera en fil
```
python encrypt_tool.py encrypt -f <filnamn> -k <nyckelfil>
```
Exempel:
```
python encrypt_tool.py encrypt -f secret.txt -k key.key
```
Detta kommer att skapa en krypterad fil secret.txt.encrypted.
Originalfilen secret.txt lämnas oförändrad.

Dekryptera en fil

```
python encrypt_tool.py decrypt -f <filnamn>.encrypted -k <nyckelfil>
```
Exempel:
```
python encrypt_tool.py decrypt -f secret.txt.encrypted -k key.key
```
Detta kommer att skapa en dekrypterad fil secret.txt.decrypted.
Du kan öppna secret.txt.decrypted för att se originalinnehållet.
Användbara alternativ:

-f, --file: Ange filnamnet på filen du vill kryptera/dekryptera.
-k, --key: Ange sökvägen till nyckelfilen.

Kända begränsningar:
Nyckelfilen måste finnas och vara korrekt för att kryptering/dekryptering ska fungera.
Filen som ska krypteras/dekrypteras måste finnas i samma katalog om inte fullständig sökväg anges.
Endast binära filer stöds; för textfiler kan extra försiktighet krävas.


Nätverksskanner
Beskrivning:
Ett verktyg som skannar nätverk och upptäcker öppna portar med hjälp av Nmap via python-nmap-biblioteket. Detta kan användas för att identifiera aktiva enheter i ett nätverk och förstå vilka tjänster som körs på dem.

Fil:
network_scanner.py - Huvudskriptet för nätverksskanning.
Användning:
Skanna specifika IP-adresser
```
python network_scanner.py --ips <ip1> <ip2> --scan
```
Exempel:
```
python network_scanner.py --ips 192.168.1.1 192.168.1.2 --scan
```
Skannar de angivna IP-adresserna och visar öppna portar och tjänster.
Ladda IP-adresser från en fil
```
python network_scanner.py --ip-file <filnamn> --scan
```
Exempel:
```
python network_scanner.py --ip-file ip_list.txt --scan
```
ip_list.txt bör innehålla en lista över IP-adresser eller värdnamn, en per rad.

Spara resultat till en fil
```
python network_scanner.py --ips <ip> --scan --output <filnamn>
```
Exempel:
```
python network_scanner.py --ips 192.168.1.1 --scan --output results.txt
```
Resultaten sparas i results.txt för senare analys.
Använd den interaktiva menyn
Kör skriptet utan argument:
```
python network_scanner.py
```
Följ anvisningarna på skärmen för att lägga till IP-adresser, skanna och spara resultat.
Användbara alternativ:
--ips: Ange en eller flera IP-adresser eller värdnamn att skanna.
--ip-file: Ange en fil som innehåller en lista över IP-adresser eller värdnamn.
--scan: Startar skanningen direkt.
--output: Ange ett filnamn för att spara resultaten.

Kända begränsningar:
Nmap krävs: Se till att Nmap är installerat och tillgängligt i din PATH.
Behörighet: Administrativa rättigheter kan krävas för vissa skanningar.
Brandväggar: Brandväggar kan blockera skanningar eller ge ofullständiga resultat.


Packet Sniffer
Beskrivning:
Ett verktyg som använder scapy för att sniffa och analysera nätverkstrafik. Detta kan användas för att övervaka nätverkstrafik på ett gränssnitt och analysera paket för felsökning eller utbildningsändamål.
Fil:
packet_sniffer.py - Huvudskriptet för paketavlyssning.
Användning:
Lista tillgängliga nätverksgränssnitt
```
python packet_sniffer.py --list
```
Visar en lista över nätverksgränssnitt som kan användas för sniffning.
Sniffa paket på ett gränssnitt

python packet_sniffer.py -i <gränssnitt>
Exempel:
```
python packet_sniffer.py -i eth0
```
Börjar sniffa paket på gränssnittet eth0 tills programmet avbryts (t.ex. med Ctrl+C).
Sniffa ett specifikt antal paket
```
python packet_sniffer.py -i <gränssnitt> -c <antal_paket>
```
Exempel:
```
python packet_sniffer.py -i eth0 -c 10
```
Sniffar 10 paket på eth0 och avslutar sedan.
Filtrera på protokoll
```
python packet_sniffer.py -i <gränssnitt> -p <protokoll>
```
Tillgängliga protokoll: tcp, udp, icmp, arp

Exempel:
```
python packet_sniffer.py -i eth0 -p tcp
```
Sniffar endast TCP-paket på eth0.
Spara fångade paket till en fil
```
python packet_sniffer.py -i <gränssnitt> -o <filnamn>
```
Exempel:
```
python packet_sniffer.py -i eth0 -o captured_packets.pcap
```
Sparar fångade paket i captured_packets.pcap, som kan öppnas med Wireshark eller liknande verktyg.
Kombinera flera alternativ
```
python packet_sniffer.py -i eth0 -c 20 -p icmp -o icmp_packets.pcap
```
Sniffar 20 ICMP-paket på eth0 och sparar dem i icmp_packets.pcap.

Användbara alternativ:
-i, --interface: Ange nätverksgränssnitt att lyssna på.
-c, --count: Antal paket att fånga (0 för obegränsat).
-p, --protocol: Protokoll att filtrera på (tcp, udp, icmp, arp).
-o, --output: Filnamn för att spara fångade paket (PCAP-format).
--list: Lista tillgängliga nätverksgränssnitt.
Kända begränsningar:

Administrativa rättigheter: På Windows kräver nätverkssniffning att programmet körs som administratör. Högerklicka på Kommandotolken och välj "Kör som administratör".
Npcap: För Windows-användare krävs Npcap installerat i "WinPcap API-compatible Mode".
Varning: Du kan få varningen WARNING: No libpcap provider available ! pcap won't be used. Detta kan ofta ignoreras om verktyget fungerar som förväntat.
Lagliga begränsningar: Använd endast verktyget på nätverk där du har tillstånd att övervaka trafiken.

Ansvarsfriskrivning
Viktigt: Denna verktygslåda är avsedd för utbildningsändamål och laglig användning inom IT-säkerhet och nätverksanalys. Otillåten användning av dessa verktyg kan bryta mot lagar och regler. Användaren ansvarar för att följa alla tillämpliga lagar och bestämmelser. Utvecklaren tar inget ansvar för felaktig eller olaglig användning av verktygen.
