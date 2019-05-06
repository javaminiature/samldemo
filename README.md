
# samldemo
SAML demo with spring boot.

#Install Certificate .

- Download utility from https://github.com/vschafer/ssl-extractor
- Run the following command to dowload the ssl certificate 
  - java -jar sslextractor-0.9.jar idp.ssocircle.com 443
- Load the certificate using the following command 
  - >keytool -import -trustcacerts -keystore cacerts -storepass changeit -noprompt -alias ssocircle -file c:\play\utility\CN=idp.ssocircle.com.cer
- Login to the applocation using 
  - http://localhost:8080/samldemo/home
