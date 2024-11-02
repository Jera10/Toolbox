import sys
import os

def display_main_menu():
    print("\n*********** Verktygslåda Meny ***********")
    print("1. Krypteringsverktyg")
    print("2. Nätverksskanner")
    print("3. Packet Sniffer")
    print("4. Avsluta")
    choice = input("Vänligen ange ett av alternativen (1-4): ")
    print("******************************************")
    return choice

def main():
    while True:
        choice = display_main_menu()
        if choice == '1':
            os.system('python encrypt_tool.py')
        elif choice == '2':
            os.system('python network_scanner.py')
        elif choice == '3':
            os.system('python packet_sniffer.py')
        elif choice == '4':
            print("Avslutar verktygslådan.")
            sys.exit(0)
        else:
            print("Ogiltigt val. Vänligen välj mellan 1-4.")

if __name__ == '__main__':
    main()
