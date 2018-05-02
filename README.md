# SEC Project - Secure Bank
  
## Installation  
**Maven is required**  
Download or clone this repository.  
Open a terminal on the project root directory and then type:  
`$ mvn install`  

## Usage

#### Server Side
At this stage the system will have to tolerate **f** number of faults and to accomplish that 
a **N** number of replicas will initiated.
The replicas will follow a Fail-Arbitrary Algorithm: Authenticated-Data Byzantine Quorum to ensure
the synchronization between them and provide a reliable service when the number of faults are under **f**.
To bootstrap the replicas simply call the **bootstrap.bat** batch file under the root server directory.
args  
`1st arg` Specifies the number of failures to tolerate, the default value is 1, which will bootstrap a total of 4 replicas
Example:  
`...\server>bootstrap.bat` Tolerate a maximum of 1 failure
or  
`...\server>bootstrap.bat 3` Tolerate a maximum of 3 failures

##### How to generate a key pair
Open a terminal on the root directory of the server project and then invoke the following java file `GenerateKeyPair`.
At this stage this process is executed automatically at the boostrap level.    
Args:  
`-n` Specifies the name of the server  
`-pw` Specifies the password that will protect the keypair on the key store  
Example:  
`mvn exec:java@GenerateKeyPair -Dexec.args="-n Server_1 -pw abc"`

##### How to start the web server
Open a terminal on the root directory of the server project and then type:  
`mvn exec:java@WebServer -Dexec.args="Server_1"`

#### Client Side
1. The client also requires a pair of keys (public and private key) which is based on the Elliptic-curve cryptography.  
2. Register his public key on the server  
3. Use any of the other client side programs that uses the interfaces the server has made available to the public.

##### How to generate a key pair
Open a terminal on the root directory of the client project and then invoke the following java file `GenerateKeyPair`.    
Args:  
`-n` Specifies the name of the client  
`-pw` Specifies the password that will protect the keypair on the key store
Example:
`mvn exec:java@GenerateKeyPair -Dexec.args="-n Client_1 -pw abc"`

##### How to register a client
Open a terminal on the root directory of the client project and then invoke the following java file `Register`.  
Args:
`n` Specifies the name of the client  
`a` Specifies the amount to initialize the account  
`ns` Specifies the number of servers available  
`pw` Specifies the password to fetch the user private key from the key store  
Example:    
`mvn exec:java@Register -Dexec.args="-n Client_1 -a 10 -ns 4 -pw abc"`

##### How to check an account
pen a terminal on the root directory of the client project and then invoke the following java file `CheckAccount`.    
Args:  
`n` Specifies the name of the client    
`ns` Specifies the number of servers available  
Example:
`mvn exec:java@CheckAccount -Dexec.args="-n Client_1 -ns 4"`

##### How to audit an account
Open a terminal on the root directory of the client project and then invoke the following java file `Audit`.  
Args:
`n` Specifies the name of the client    
`ns` Specifies the number of servers available  
Example:  
`mvn exec:java@Audit -Dexec.args="-n Client_1 -ns 4"`

##### How to send money
Open a terminal on the root directory of the client project and then invoke the following java file `SendAmount`.  
`-sn` specifies the name of the client sending the amount  
`-tn` specifies the name of the client who will receive  the amount  
`-a` specifies the amount to send  
`ns` Specifies the number of servers available  
`pw` Specifies the password to fetch the client, sending the amount, private key from the key store  
Example:  
`mvn exec:java@SendAmount -Dexec.args="-sn Client_1 -tn Client_2 -a 1000 -ns 4 -pw abc"`

##### How to accept a pending transaction
First, use `CheckAccount` to obtain the list of pending transactions.
Copy the signature of the transaction you want to accept and use `ReceiveAmount`.  
Args:  
`n` Specifies the name of the client that is receiving the amount  
`ts` Specifies the signature of the transaction to the receive the amount  
`ns` Specifies the number of servers available    
`pw` Specifies the password to fetch the user private key from the key store  
Example:  
`mvn exec:java@ReceiveAmount -Dexec.args="-n Client_2 -ts MEYCIQDEe4XFwURKGMjC0ge7eVIT5B2/Rgp/R77m9t17sIVPugIhAIZCXzIO0GikCYAjYPjiuEUPs7K7xDn/3A4us+6UUqID -ns 4 -pw abc"`

## Tests

##### How to run tests on the server 
Open a terminal on the root directory of any project and then type:  
`mvn clean test -DskipTests=false`

## Documentation
A small report documenting the solution and its security features at a high level, as well as sequence diagrams for each
of the five main operations supported by the server and client, can be found in the `docs` folder.

## License  
Licensed under MIT. See [LICENSE](LICENSE) for more information. 
