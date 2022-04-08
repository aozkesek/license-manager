# License Manager 

**A Simple Software License Application**  
License Manager has three -3- parts.  These are a static library liblicense, an 
acquirer executable license_customer and an issuer executable license_provider.

* **liblicense**
A static library depended to the openssl crypto library contains functions and 
type definitions.  


* **license_customer**
An executable used to generate initial license file for application, services, 
modules.


* **license_provider**
An executable used to generate final license file from initial one.  

**Creating a License File**

Running **license_provider** or **license_customer** executable generates RSA private/public
keys and saves them under working directory as **provider.pem, provider-pub.pem and 
customer.pem, customer-pub.pem**.  Keep provider-pub.pem together with license_customer
executable.

* **license_customer**<br>
loads customer's RSA key,<br>
loads provider's RSA public key,<br>
generates a session key,<br>
encrypts session key with provider's public key,<br>
builds a license json string from given command-line arguments,<br>
encrypts license-json-string with session key,<br>
saves encrypted session key, customer public key and encrypted license-json-string
into **customer.lic** file,<br>
send customer.lic file to the provider's office, manually.

* **license_provider**<br>
loads provider's RSA key,<br>
loads customer.lic file,<br>
parses encrypted session key,<br>
decrypts session key with provider's private key,<br>
parses customer's public key,<br>
creates customer's RSA key from the public key,<br>
parses encrypted license-json-string,<br>
decrypts license-json-string with session key,<br>
build a final license-json-string from given command-line arguments,<br>
calculates a hash value from license-json-string,<br>
encrypts the hash value with customer's public key,<br>
saves final license-json-string and it's encrypted hash value into **customer.license**
file,<br>
send customer.license file to the customer's office, manually.

**Sample command-line arguments**

* **license_customer** client-name provider's-rep-name app-version 
feature-or-service-name:version feature-or-service-name-2:version-2 ...

* **license_provider** 3650
* **license_provider** demo

