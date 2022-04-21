from django.conf import settings

from django_rest_crypto.encrypt import EncryptData


class EncryptDataMiddleware(object):
    def __init__(self, get_response):
       self.get_response = get_response

    def __call__(self, request):
       response = self.get_response(request)
       return response

    def process_template_response(self, request, response):

      if hasattr(response, 'data') and response.data.get('data'):
         raw_data = response.data.get('data')

         ed = EncryptData(raw_data, settings.ENCRYPT_KEY)

         mode = settings.ENCRYPT_MODE if hasattr(settings, 'ENCRYPT_MODE') else 'CBC'

         payload = {}
         if hasattr(settings, 'ENCRYPT_IV'):
                payload['iv'] = settings.ENCRYPT_IV
         if hasattr(settings, 'ENCRYPT_NONCE'):
            payload['nonce'] = settings.ENCRYPT_NONCE
         
         response.data['data'] = ed.encrypt(mode=mode, **payload)

      return response
