SEC Project - Secure Bank
=================

breve descricacao do que e......
  
### Installation  
----------------  
**Maven is needed**  
Download or clone this repository.  
Open a terminal on the project root directory and then type:  
`$ mvn install`  

 
    
### Usage
#### Execute the webserver
From the project root directory:

```
mvn exec:java -pl server
```
Or from the server project root directory:
```
mvn exec:java
```

mvn exec:java -Dexec.mainClass="server"
mvn exec:java -Dexec.mainClass="client"
mvn exec:java -Dexec.mainClass="client.GenerateKeyPair"

exe: mvn exec:java@ID -Dexec.args="arg1 arg2 arg3"

GenerateKeyPair for a client:
	dentro da pasta client: mvn exec:java@GenerateKeyPair -Dexec.args="-n Client_1"

GenerateKeyPair for a server:	
	dentro da directoria server: mvn exec:java@GenerateKeyPair -Dexec.args="-n Server_1"
	
Execute webserver:
	dentro da directoria server: mvn exec:java@WebServer

#### How to use the client
1. Each client needs to generate a key pairs which is based on the Elliptic-curve cryptography, which is an approach to public-key cryptography.
2. 

### Documentation
Read the documentation in [DOCUMENTATION](DOCUMENTATION.md).  

### License  
Licensed under MIT. See [LICENSE](LICENSE) for more information. 