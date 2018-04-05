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

##### How to send money
`-ns` specifies the name of the client sending the amount

`-nt` specifies the name of the client who will receive

`-a` specifies the amount to send

Example:

`mvn exec:java@SendAmount -Dexec.args="-ns Client_1 -nt Client_2 -s Server_1 -a 1000"`

##### How to accept a pending transaction
First, use `CheckAccount` to obtain the list of pending transactions.
Take the signature of the transaction you want to accept and use `ReceiveAmount`:

`mvn exec:java@ReceiveAmount -Dexec.args="-n Client_2 -s Server_1 -ts MEYCIQDEe4XFwURKGMjC0ge7eVIT5B2/Rgp/R77m9t17sIVPugIhAIZCXzIO0GikCYAjYPjiuEUPs7K7xDn/3A4us+6UUqID"`

## Tests

##### How to run tests on the server 
Open a terminal on the root directory of any project and then type:  
`mvn clean test -DskipTests=false`

## Documentation
A small report documenting the solution and its security features at a high level, as well as sequence diagrams for each
of the five main operations supported by the server and client, can be found in the `docs` folder.

## License  
Licensed under MIT. See [LICENSE](LICENSE) for more information. 
