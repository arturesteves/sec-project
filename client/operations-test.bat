@echo off
echo.
echo -------------------------BEGIN-------------------------
SET numberReplicas=4


:: GENERATE KEY PAIRS
echo Generate a KeyPair for Client_1
start /wait cmd /c mvn exec:java@GenerateKeyPair -Dexec.args="-n Client_1 -pw abc"

echo Generate a KeyPair for Client_2
start /wait cmd /c mvn exec:java@GenerateKeyPair -Dexec.args="-n Client_2 -pw abc"


:: GENERATE KEY PAIRS
echo Register Client_1
start /wait cmd /k mvn exec:java@Register -Dexec.args="-n Client_1 -a 50 -ns %numberReplicas% -pw abc"
echo Register Client_2
start /wait cmd /k mvn exec:java@Register -Dexec.args="-n Client_2 -a 50 -ns %numberReplicas% -pw abc"


:: CHECK ACCOUNTS
echo Check account of Client_1
start /wait cmd /k mvn exec:java@CheckAccount -Dexec.args="-n Client_1 -ns %numberReplicas%"


:: AUDIT ACCOUNTS
echo Audit account of Client_1
start /wait cmd /k mvn exec:java@Audit -Dexec.args="-n Client_1 -ns %numberReplicas%"


:: SEND AMOUNTS
echo Send Amount from Client_1 to Client_2
start /wait cmd /k mvn exec:java@SendAmount -Dexec.args="-sn Client_1 -tn Client_2 -a 5 -ns %numberReplicas% -pw abc"


:: AUDIT ACCOUNTS
echo Audit account of Client_1
start /wait cmd /k mvn exec:java@Audit -Dexec.args="-n Client_1 -ns %numberReplicas%"


echo -------------------------END-------------------------
echo.
