import hashlib
import requests
from urllib.parse import urlencode

class RTM_Ninja:
    api_key = '6f098ddab33f7a5adc80cb759c78c42b'
    secret = '4a47d0c5edc5cab3'
    token = None
    frob = None
    timeline = None
    list_of_lists = None
    
    def __init__(self):
        if self.token == None:
            success = self.get_token_from_file()
        if success == False:
            self.get_new_token()
            self.save_token_to_file()
    
    def get_token_from_file(self):
        print("Trying to fetch a token from a local file")
        try:
            save_file = open('token_file', 'r')
            self.token = save_file.readline()
            save_file.close()
            return True
        except:
            print("Couldn't read a token file")
        return False
        
    def save_token_to_file(self):
        print("Trying to write a token to a local file")
        try:
            save_file = open('token_file', 'w')
            save_file.write(self.token)
            save_file.close()
        except:
            print("Failed to write the token to a file")
    
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
        print("Current token is valid")
        response = self.call_rtm_func(method='rtm.auth.checkToken', auth_token=self.token)
        if self.got_a_successful(response):
            return True
        return False

    def get_new_token(self):
        print("Trying to get a new token for you")
        self.get_new_frob()

        params = {"perms": "delete",
          "api_key": self.api_key,
          "frob": self.frob
          }
        params['api_sig'] = self.sign(params)
        print("I think I lost the token somewhere. Please authorise me again. Ctrl+Click on this link:\n" \
              + "http://www.rememberthemilk.com/services/auth/" + "?" + urlencode(params))
        
        input("\n\nPress enter when you are done authorising me")

        response = self.call_rtm_func(method='rtm.auth.getToken', frob=self.frob)

        if self.got_a_successful(response):
            self.token = response['auth']['token']
            print("Got a new token")
        else:
            print("Failed to get a token.\nError: " + response['err']['msg'])

    def get_new_frob(self):
        print("Trying to get a new frob")
        response = self.call_rtm_func(method='rtm.auth.getFrob', frob=self.frob)
        if self.got_a_successful(response):
            self.frob = response['frob']
            print("Received a frob succesfully")
        else:
            print("Failed to get a new frob.\nError: " + response['err']['msg'])
    
    def create_timeline(self):
        print("Attempting to create a timeline")
        response = self.call_rtm_func(method='rtm.timelines.create', auth_token=self.token)
        if self.got_a_successful(response):
            self.timeline = response['timeline']
            print("Created a timeline: " + self.timeline)
        else:
            print("Failed to create a timeline.\n" + response['err']['msg'])

    def get_list_of_lists(self):
        print("Trying to get a list of lists")
        response = self.call_rtm_func(method='rtm.lists.getList', auth_token=self.token)
        if self.got_a_successful(response):
            self.list_of_lists = response['lists']['list']
            print("Got your list of lists")
            for list in self.list_of_lists:
                print(list['name'] + " : " + list['id'])
        else:
            print("Failed to retrieve the list of lists.\n" + response['err']['msg'])
    
    def get_tasks(self):
        print("Trying to get the tasks in your inbox")
        response = self.call_rtm_func(method='rtm.tasks.getList', auth_token=self.token)
        print(response)
        
    def call_rtm_func(self, method=None, auth_token=None, scheme='json', frob=None, list_id=None, task_filter=None):
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
            
        if task_filter:
            params['filter'] = task_filter

        params['api_key'] = self.api_key
        params['api_sig'] = self.sign(params)

        response_data = requests.get("https://api.rememberthemilk.com/services/rest/", params = params)

        json_data = response_data.json()

        return json_data['rsp']

if __name__ == "__main__":
    ninja = RTM_Ninja()

    #if ninja.token_is_valid() == False:
     #   ninja.get_new_token()
      #  ninja.save_token_to_file()
        
#    ninja.create_timeline()
#    ninja.get_list_of_lists()
    ninja.get_tasks()
