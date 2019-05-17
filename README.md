# SCRAM-mysql-php-client
Клиент scram авторизации на PHP

Encryptor передается в Url, пример:  
http://scramc/?encryptor=openssl  
или  
http://scramc/?encryptor=phphash  

сначала дергается метод ядра:  
/auth/first-message  
в теле пост передаётся логин юзера:  
{
    "userName": "admin_mysql_sha1",
}


ядро возвращает ответ в виде:  
`
{
         "userName": "admin_mysql_sha1",
         "serverNonce": "793A4B72859A775445F8400E9481AFD3BACAD69F",
         "encryptedServerNonce": "96BE15A60721B3F54DEB82C6594BC4384A3EE1361A82B7CC7A00735F0A4A626421C4F7ED413E32FA26AFD928368AFA5A",
         "authMode": "MYSQL_SHA1"
 }
 `
 
 
 вычисляешь clientProof и дергаешь метод ядра:  
 /auth/final-message  
 {
         "userName": "admin_mysql_sha1",
         "serverNonce": "793A4B72859A775445F8400E9481AFD3BACAD69F",
         "encryptedServerNonce": "96BE15A60721B3F54DEB82C6594BC4384A3EE1361A82B7CC7A00735F0A4A626421C4F7ED413E32FA26AFD928368AFA5A",
         "clientProof": "рассчитанный client proof"
 }
 
 #### итоговый вариант scram:   
 SaltedPassword := Hi(Normalize(password), salt, i)  
 ClientKey := HMAC(SaltedPassword, "")  
 StoredKey := H(ClientKey)  
 AuthMessage := client-nonce + server-nonce   
 ClientSignature := HMAC(StoredKey, UNHEX(AuthMessage))  
 ClientProof := ClientKey XOR ClientSignature  
 
 
 #### Hi(str, salt, i):  
 
 U1 := HMAC(str, salt + INT(1))  
 U2 := HMAC(str, U1)  
 ...  
 Ui-1 := HMAC(str, Ui-2)  
 Ui := HMAC(str, Ui-1)  
 
 Hi := U1 XOR U2 XOR ... XOR Ui  