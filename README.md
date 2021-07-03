# JwtAuthentication
The Alomost Complite And Secure  Authentication Api Source Code

Please after download source code run ```Update-database``` in packege manage console to create database from migrations.

## Note
In ```RecoveryPassword``` action in ```Get``` method you must send your email. after that applicaton send a email contain token and email. please implement action in your app to get and save token and email then get yousr new password from input and finaly send body with post requst to ```RecoveryPassword``` all of them( ```Email``` , ```Token``` , ```NewPassword```)
