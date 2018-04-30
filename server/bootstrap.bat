setlocal enabledelayedexpansion
echo ""
echo "Bootstraping the servers..."
echo.

:: number of failure tolerated
SET f=2
:: number of replicas necessary to tolerate f failures 
SET /a N=(%f%*2)+1
:: servers base info
SET protocolHost="http://localhost"
SET port=4570

SET i=1
SET /a N=N+1
echo "i: %i% , f: %f%, N: %N%"
::SET serverPorts
::SET serverNames


for /l %%x in (1, 1, %N%) do (
	echo "Generating a key pair for replica !i!"
	echo.
	:: generate server key pair on a new command line
	start cmd /c mvn exec:java@GenerateKeyPair -Dexec.args="-n Server_!i!"
	TIMEOUT /t 10
	start cmd /k mvn exec:java@WebServer -Dexec.args="Server_!i!"
	SET /a i=!i!+1
)


echo "All servers initialized with success!"
echo.

:: define a function
:getStringServers
