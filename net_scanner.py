import os
import nmap
import socket
import ipaddress
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Nmap IP-skanningsverktyg')

    # Användaren kan ange en eller flera IP-adresser eller värdnamn
    parser.add_argument('-i', '--ips', nargs='+', help='IP-adresser eller värdnamn att skanna')

    # Användaren kan ange en fil med IP-adresser
    parser.add_argument('-f', '--ip-file', help='Fil som innehåller IP-adresser att skanna')

    # Användaren kan ange ett output-filnamn
    parser.add_argument('-o', '--output', help='Filnamn för att spara skanningsresultat')

    # Flagga för att starta skanningen direkt
    parser.add_argument('-s', '--scan', action='store_true', help='Starta skanningen direkt')

    args = parser.parse_args()
    return args

def display_menu():
    print("\n*********** Nmap IP Skanningsmeny ***********")
    print("1. Ange IP adresser manuellt.")
    print("2. Ladda in IP addresser från fil.")
    print("3. Starta scan.")
    print("4. Spara resultat.")
    print("5. Avsluta.")
    choice = input("Vänligen ange ett av alternativen (1-5): ")
    print("************************************************")
    return choice

def manual_ip_input(ip_list):
    inputs = input("Ange IP addresser, hostnamn, eller helt nätverk, separerat med mellanslag: ")
    entries = inputs.strip().split()
    valid_entries = []
    for entry in entries:
        if is_valid_ip_or_hostname_or_network(entry):
            valid_entries.append(entry)
        else:
            print(f"Ogiltig IP adress, hostnamn, eller nätverk skippas: {entry}")
    ip_list.extend(valid_entries)
    print(f"Aktuell IP lista: {ip_list}")

def is_valid_ip_or_hostname_or_network(input_str):
    # Kolla om det är en legitim IP adress
    try:
        socket.inet_aton(input_str)
        return True
    except socket.error:
        pass

    # Kolla om hostnamnet är legit
    try:
        socket.gethostbyname(input_str)
        return True
    except socket.error:
        pass

    # Kolla om nätverket stämmer
    try:
        ipaddress.ip_network(input_str, strict=False)
        return True
    except ValueError:
        pass

    return False

    
def load_ips_from_file(ip_list):
    filename = input("Ange filnamn: ")
    try:
        with open(filename, 'r') as file:
            for line in file:
                ip_list.extend(line.strip().split())
        print(f"Laddade IPs: {ip_list}")
    except FileNotFoundError:
        print("Filen kunde inte hittas. Vänligen försök igen.")

def scan_ips(ip_list, scan_results):
    if not ip_list:
        print("Finns inga IP-adresser att skanna. Vänligen lägg till IP-adresser först.")
        return
    nm = nmap.PortScanner()
    for ip in ip_list:
        print(f"Skannar {ip}...")
        try:
            nm.scan(ip, arguments='-sS -sV -A -T3') # Skulle varit bra att inkludera så att programmet tar emot dessa argument som input av anv
            if ip in nm.all_hosts():
                scan_results[ip] = nm[ip]
                print(f"Skanning av {ip} klar.")
            else:
                print(f"{ip} är nere eller svarar inte.")
        except Exception as e:
            print(f"Skanningsfel på {ip}: {e}")
    print("Skanningsprocess klar.")

def save_results(scan_results, output_file=None):
    if not scan_results:
        print("Finns inget resultat att spara.")
        return

    if output_file:
        try:
            with open(output_file, 'w') as file:
                write_results_to_file(file, scan_results)
            print(f"Resultat sparade i '{output_file}'.")
        except Exception as e:
            print(f"Kunde inte spara resultat: {e}")
        return

    # Om inget output-filnamn har angetts, använd den interaktiva menyn
    print("\n--- Spara Resultat ---")
    print("1. Spara i ny fil")
    print("2. Infoga till befintlig txt fil.")
    print("3. Skriv ut resultat i terminal.")
    choice = input("Vänligen välj alternativ 1-3: ")

    if choice == '1':
        filename = input("Ange nytt filnamn (t.ex, results.txt): ")
        filepath = os.path.join(os.getcwd(), filename)
        try:
            with open(filepath, 'w') as file:
                write_results_to_file(file, scan_results)
            print(f"Resultat sparat i; {filepath}")
        except Exception as e:
            print(f"Resultat kunde inte sparas: {e}")

    elif choice == '2':
        txt_files = [f for f in os.listdir(os.getcwd()) if f.endswith('.txt')]
        if not txt_files:
            print("Inga befintliga .txt filer kunde hittas i aktuell mapp.")
            return
        print("\nBefintliga .txt filer:")
        for idx, f in enumerate(txt_files, start=1):
            print(f"{idx}. {f}")
        file_choice = input("Välj filnummer: ")
        try:
            file_idx = int(file_choice) - 1
            if 0 <= file_idx < len(txt_files):
                filepath = os.path.join(os.getcwd(), txt_files[file_idx])
                with open(filepath, 'a') as file:
                    write_results_to_file(file, scan_results)
                print(f"Resultatet infogat till: {filepath}")
            else:
                print("Ogiltigt val")
        except ValueError:
            print("Ogiltig input. Vänligen ange ett nummer.")
        except Exception as e:
            print(f"Kunde inte infoga resultat: {e}")
    elif choice == '3':
        print(scan_results)
    else:
        print("Ogiltig input. Vänligen välj alternativ '1', '2' eller '3'.")
        
def write_results_to_file(file, scan_results):
    for ip, result in scan_results.items():
        file.write(f"Resultat för {ip}:\n")
        protocols = result.all_protocols()
        if not protocols:
            file.write("Inga öppna portar hittades.\n")
        else:
            for proto in protocols:
                lport = result[proto].keys()
                for port in sorted(lport):
                    port_info = result[proto][port]
                    state = port_info['state']
                    service = port_info['name']
                    version = port_info.get('version', '')
                    if version:
                        file.write(f"Port: {port}\tState: {state}\tService: {service}\tVersion: {version}\n")
                    else:
                        file.write(f"Port: {port}\tState: {state}\tService: {service}\tVersion: Okänd\n")
            file.write("\n")


def main():
    args = parse_arguments()
    ip_list = []
    scan_results = {}

    # Om användaren har angett IP-adresser via kommandoraden
    if args.ips:
        for entry in args.ips:
            if is_valid_ip_or_hostname_or_network(entry):
                ip_list.append(entry)
            else:
                print(f"Ogiltig IP-adress eller värdnamn: {entry}")

    # Om användaren har angett en fil med IP-adresser
    if args.ip_file:
        try:
            with open(args.ip_file, 'r') as file:
                for line in file:
                    entries = line.strip().split()
                    for entry in entries:
                        if is_valid_ip_or_hostname_or_network(entry):
                            ip_list.append(entry)
                        else:
                            print(f"Ogiltig IP-adress eller värdnamn i filen: {entry}")
        except FileNotFoundError:
            print(f"Filen '{args.ip_file}' hittades inte.")

    # Om användaren har valt att starta skanningen direkt
    if args.scan and ip_list:
        scan_ips(ip_list, scan_results)
    elif args.scan and not ip_list:
        print("Inga giltiga IP-adresser att skanna. Vänligen ange IP-adresser.")
        return

    # Om användaren har angett ett output-filnamn
    if args.output and scan_results:
        try:
            with open(args.output, 'w') as file:
                write_results_to_file(file, scan_results)
            print(f"Resultat sparade i '{args.output}'.")
        except Exception as e:
            print(f"Kunde inte spara resultat: {e}")
    elif args.output and not scan_results:
        print("Inga skanningsresultat att spara.")

    # Om inga kommandoradsargument har angetts, använd den interaktiva menyn
    if not any(vars(args).values()):
        while True:
            choice = display_menu()
            if choice == '1':
                manual_ip_input(ip_list)
            elif choice == '2':
                load_ips_from_file(ip_list)
            elif choice == '3':
                scan_ips(ip_list, scan_results)
            elif choice == '4':
                save_results(scan_results)
            elif choice == '5':
                print("Avslutar programmet.")
                break
            else:
                print("Ogiltigt val. Vänligen välj mellan 1-5.")

