# SEC Project - Secure Bank
  
## Installation  
**Maven is required**  
Download or clone this repository.  
Open a terminal on the project root directory and then type:  
`$ mvn install`  

## Usage

#### Server Side
1. First we need to generate a pair of keys (public and private key) which is based on the Elliptic-curve cryptography.
2. We need to start the web server.

##### How to generate a key pair
Open a terminal on the root directory of the server project and then type:  
`mvn exec:java@GenerateKeyPair -Dexec.args="-n Server_1"`
  
##### How to start the web server
Open a terminal on the root directory of the server project and then type:  
`mvn exec:java@WebServer -Dexec.args="Server_1"`

#### Client Side
1. The client also requires a pair of keys (public and private key) which is based on the Elliptic-curve cryptography.  
2. Register his public key on the server  
3. Use any of the other client side programs that uses the interfaces the server has made available to the public.

##### How to generate a key pair
Open a terminal on the root directory of the client project and then type:  
`mvn exec:java@GenerateKeyPair -Dexec.args="-n Client_1"`

##### How to register a client
Open a terminal on the root directory of the client project and then type:  
`mvn exec:java@Register -Dexec.args="-n Client_1 -s Server_1 -a 10"`

##### How to check an account
Open a terminal on the root directory of the client project and then type:  
`mvn exec:java@CheckAccount -Dexec.args="-n Client_1 -s Server_1"`

##### How to audit an account
Open a terminal on the root directory of the client project and then type:  
`mvn exec:java@Audit -Dexec.args="-n Client_1 -s Server_1"`

## Tests

##### How to run tests on the server 
Open a terminal on the root directory of any project and then type:  
`mvn clean test`

## Documentation
The client side programs documentation can be found at [CLIENT-DOC](docs/CLIENT-DOCUMENTATION.md).   
The server side programs documentation can be found at [SERVER-DOC](docs/SERVER-DOCUMENTATION.md).  
The web server api documentation can be found at [SERVER-API-DOC](docs/SERVER-API-DOCUMENTATION.md).

## License  
Licensed under MIT. See [LICENSE](LICENSE) for more information. 
