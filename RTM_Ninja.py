import hashlib
import requests
from urllib.parse import urlencode

class RTM_Ninja:
    api_key = '6f098ddab33f7a5adc80cb759c78c42b'
    secret = '4a47d0c5edc5cab3'
    token = 'c9a926aa92ff21284eb3e682374ae2540aa6a834'
    frob = None
    timeline = None
    
    def sign(self, params=None):
        pairs = ''.join(['%s%s' % (k, v) for k, v in self.sortedItems(params)])
        return hashlib.md5((self.secret + pairs).encode('utf-8')).hexdigest()

    def sortedItems(self, dictionary):
        "Return a list of (key, value) sorted based on keys"
        keys = list(dictionary.keys())
        keys.sort()
        for key in keys:
            yield key, dictionary[key]
            
    def got_a_successful(self, response):
        if response['stat'] == 'ok':
            return True
        return False

    def token_is_valid(self):
        response = self.call_rtm_func(method='rtm.auth.checkToken', auth_token=self.token)
        if self.got_a_successful(response):
            return True
        return False

    def get_new_token(self):
        self.get_new_frob()

        params = {"perms": "delete",
          "api_key": self.api_key,
          "frob": self.frob
          }
        params['api_sig'] = self.sign(params)
        print("Please authorise me. I think I lost the token somewhere. Go here:\n" \
              + "http://www.rememberthemilk.com/services/auth/" + "?" + urlencode(params))
        
        input("\n\nPress enter when you are done authorising me")

        response = self.call_rtm_func(method='rtm.auth.getToken', frob=self.frob)
        print(response)
        if self.got_a_successful(response):
            self.token = response['auth']['token']
        else:
            print("Failed to get a token.\nError: " + response['err']['msg'])

    def get_new_frob(self):
        response = self.call_rtm_func(method='rtm.auth.getFrob', frob=self.frob)
        if self.got_a_successful(response):
            self.frob = response['frob']
            print(self.frob)
        else:
            print("Failed to get a new frob.\nError: " + response['err']['msg'])
    
    def create_timeline(self):
        response = self.call_rtm_func(method='rtm.timelines.create', auth_token=self.token)
        if self.got_a_successful(response):
            self.timeline = response['timeline']
        else:
            print("Failed to create a timeline.\n" + response['err']['msg'])

    def call_rtm_func(self, method=None, auth_token=None, scheme='json', frob=None, list_id=None):
        if method == None:
            print("Can't read your mind yet. Specify a method")
            return

        params = {}
        params['method'] = method

        if auth_token:
            params['auth_token'] = auth_token

        if scheme:
            params['format'] = scheme

        if frob:
            params['frob'] = frob

        if list_id:
            params['list_id'] = list_id

        params['api_key'] = self.api_key
        params['api_sig'] = self.sign(params)

        response_data = requests.get("https://api.rememberthemilk.com/services/rest/", params = params)

        json_data = response_data.json()

        return json_data['rsp']

if __name__ == "__main__":
    ninja = RTM_Ninja()

    if ninja.token_is_valid() == False:
        ninja.get_new_token()
        
    ninja.create_timeline()
    
