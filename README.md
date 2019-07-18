# SCRAM-mysql-php-client
Клиенты scram авторизации на PHP и JS  
На текущий момент работает 2 варианта авторизации:
* Простая - передача BSAUTH в заголовке
* half SCRAM - ограниченный вариант SCRAM Авторизации

### 1 JS SCRAM client  
В этом репозитории на JS реализованна только SCRAM и MYSQL авторизация (в файле js_scram.html)  
Для запуска тестового кода js_scram.html необходимо запускать в хроме с отключеной защитой CORS.  
Инструкция: https://alfilatov.com/posts/run-chrome-without-cors/  
Обязательно должен быть установлен мета тег:  
`<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">`
 
### 2 PHP simple/halfSCRAM/SCRAM client

В PHP клиенте реализован паттерн-стратегия которая выбирает текущий вариант авторизации в зависимости от ответа сервера 
на первом шаге либо от параметров инициализации
Реализованы simple/MYSQL-scram/halfScram/SCRAM варианты  авторизаций  


Возможен выбор кодировщика внутри PHP openssl или phphash      
Encryptor передается в Url, пример:  
http://scramc/?encryptor=openssl  
или  
http://scramc/?encryptor=phphash  

описание тестовых данных смотри в ok_data.txt

```
сначала дергается метод ядра:  
/auth/challenge  
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
 /auth/proof  
 {
         "userName": "admin_mysql_sha1",
         "serverNonce": "793A4B72859A775445F8400E9481AFD3BACAD69F",
         "encryptedServerNonce": "96BE15A60721B3F54DEB82C6594BC4384A3EE1361A82B7CC7A00735F0A4A626421C4F7ED413E32FA26AFD928368AFA5A",
         "clientProof": "рассчитанный client proof"
 }
 ```
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
 
 
## Какие поля учавствуют в HALF-SCRAM авторизации
half SCRAM состоит из одного шага.  
Сервер автоматически проверяет наличие нужных полей и если имеется полный комплект тогда активируется 
соответствующая авторизация.  
Вот список заголовков (headers) передаваемых в случае ограниченной scram авторизации:
```
    'customer-key' => Кодовое название клиента
    'service-key' => Ключ сервиса в формате UUID v4 без тире "-"
    'service-nonce' => Случайная строка HEX длиной 40символов
    'service-timestamp' => Unix timestamp в HEX формате
    'service-proof' => (clientProof) Вычисляемое клиентом значение по формуле.
```
Формула:
``` 
    i = Количество итераций для функции hash_pbkdf2
    algo = Алгоритм хеширования, например sha или sha512
    saltedPassword = hash_pbkdf2(algo, password, hex2bin(salt), i);
    ClientKey = hash_hmac(algo,"",hex2bin(saltedPassword),0);
    
    authMessage = timestamp . serviceNonce . serviceKey;
    storedKey:= hash(ClientKey)
    clientSignature:= hash_hmac(algo, authMessage, storedKey)
    clientProof := ClientKey XOR clientSignature
