from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload


CREDENTIALS_FILE = 'gestion_archivos/credentials/long-star-438815-m0-afb3b41c32e4.json'

FOLDER_ID = '1NhdiFATcawAk2nOUlpMGmu10qQq_pIyU'
 

def get_gdrive_service():
    SCOPES = ['https://www.googleapis.com/auth/drive']
    creds = service_account.Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=SCOPES)
    service = build('drive', 'v3', credentials=creds)
    return service

def upload_to_drive(file_path, file_name):
    service = get_gdrive_service()
    
  
    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID] 
    }
    
    media = MediaFileUpload(file_path, resumable=True)
    
   
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    
    print(f"File ID: {file.get('id')}")
    return file.get('id')  