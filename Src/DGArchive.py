import requests
from requests.auth import HTTPBasicAuth


class DGArchive:

    def __init__(self,URL):
        self.URL = "https://dgarchive.caad.fkie.fraunhofer.de/r/"
        self.URL = self.URL + URL

    def check_status(self):
        # sending get request and saving the response as response object
        # to use this feature get login username and password from DGAArchive
        username ='test'
        password = 'password'
        #r = requests.get(url = self.URL, auth=HTTPBasicAuth('', ''))
        r = requests.get(url = self.URL, auth=HTTPBasicAuth(username, password))

        #print(r.status_code , r.headers ,r.content)

        # extracting data in json format
        data = r.json()

        if len(data['hits']) > 0:
            DGA_Family = data['hits'][0]['family']
            DGA_validity = data['hits'][0]['validity']['from'] + " to " + data['hits'][0]['validity']['to']
            return(("DGA Family   : %s\nDGA Validity : %s"%(DGA_Family, DGA_validity)))
        else:
            return ("Clean")

