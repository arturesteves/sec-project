@echo off
setlocal enabledelayedexpansion
echo.
echo Bootstraping the servers...
echo.

:: set to a default number of failures to tolerate
if "%~1"=="" SET f=1
if not "%~1"=="" SET f=%~1


:: number of replicas necessary to tolerate f failures, using a Fail-Arbitrary Algorithm: Authenticated-Data Byzantine Quorum
:: N > 3f
SET /a N=(%f%*3)+1
:: servers base info
SET protocolHost=http://localhost
SET port=4570
SET server_prefix=Server_
SET aliasPrefixPw=ABCD


SET i=1
echo Number of supported failures: %f%
echo Number of Replicas: %N%
echo.

:: generate keys
for /l %%x in (1, 1, %N%) do (
	echo Generating a key pair for the following replica: %server_prefix%!i!
	SET password=!aliasPrefixPw!%%x
	:: generate server key pair on a new command line
	start cmd /k mvn exec:java@GenerateKeyPair -Dexec.args="-n %server_prefix%!i! -pw !password!"
	TIMEOUT /t 10 /nobreak

	SET /a i=!i!+1
	SET /a port=!port!+1
)

SET i=1
SET port=4570

echo Wait until init the replicas
TIMEOUT /t 15 /nobreak

SET password=
:: init repicas
for /l %%x in (1, 1, %N%) do (
	echo Starting the following replica %server_prefix%!i!
	SET password=!aliasPrefixPw!%%x
	start cmd /k mvn exec:java@WebServer -Dexec.args="Server_!i! !port! %N% !password!"
	TIMEOUT /t 5 /nobreak
	SET /a i=!i!+1
	SET /a port=!port!+1
)

echo All replicas initialized with success!
echo.

