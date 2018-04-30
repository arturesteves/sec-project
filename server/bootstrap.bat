@echo off
setlocal enabledelayedexpansion
echo.
echo Bootstraping the servers...
echo.

:: number of failure tolerated
SET f=1
:: number of replicas necessary to tolerate f failures 
SET /a N=(%f%*2)+1
:: servers base info
SET protocolHost=http://localhost
SET port=4570
SET server_prefix=Server_

:: will contain the a list of server information, information compose by server url and server name
SET serversInfo=

call:getStringServers

SET i=1
echo Number of supported failures: %f%
echo Number of Replicas: %N%
echo.

for /l %%x in (1, 1, %N%) do (
	echo Generating a key pair for the following replica: %server_prefix%!i!
	echo.
	:: generate server key pair on a new command line
	start cmd /c mvn exec:java@GenerateKeyPair -Dexec.args="-n %server_prefix%!i!"
	TIMEOUT /t 10
	
	echo Starting the following replica %server_prefix%!i!
	echo.
	start cmd /k mvn exec:java@WebServer -Dexec.args="Server_!i! !port!%serversInfo%"
	echo.
	echo.
	echo.
	echo.
	echo !serversInfo!
	SET /a i=!i!+1
	SET /a port=!port!+1
)

echo All servers initialized with success!
echo.


:getStringServers
	echo Generate a string with all the severs info
	echo.
	SET j=1
	SET nextPort=%port%
	SET server=%protocolHost%:!nextPort! %server_prefix%!j!
		
	for /l %%x in (1, 1, %N%) do (
		SET serversInfo=!serversInfo! !server!
		SET /a nextPort=!nextPort!+1
		SET /a j=!j!+1
		SET server=%protocolHost%:!nextPort! %server_prefix%!j!
	)
	
GOTO:EOF
