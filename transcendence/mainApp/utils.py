from google.cloud import translate_v2 as translate 
import os

def translate_text(text, target_language):
    if target_language == 'ct':
        return ' '.join(['meow' for word in text.split()])
        
    if target_language == 'nl':
        return text
    return text
    # os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = r"/app/mainApp/googlekey.json"
    # translate_client = translate.Client()

    # if target_language == 'en':
    #     target_language = 'en-gb'
    # result = translate_client.translate(text, target_language=target_language)
    # return result["translatedText"]

