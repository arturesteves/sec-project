package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.*;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Register;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Main;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Server;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;

import static org.mockserver.model.HttpClassCallback.callback;
import static org.mockserver.model.HttpForward.forward;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import static org.mockserver.model.HttpTemplate.template;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TestWebServerTest {
    
    private static String keyStoreFilePath = null;

    private String getPreviousHash(Client client, ECPublicKey clientPublicKey) throws AuditException {
        Serialization.AuditResponse transactionsClient1 =  client.audit(clientPublicKey);
        return transactionsClient1.ledger.transactions.get(transactionsClient1.ledger.transactions.size() - 1).signature;
    }

    private ECPrivateKey getPrivateKey(String party) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        String password = "abc";
        if(party.startsWith("Server_")) {
            int serverNum = Integer.parseInt(party.substring("Server_".length()));
            password = "ABCD" + Integer.toString(serverNum);
        }

        return Utils.loadPrivateKeyFromKeyStore(getKeyStoreFilePath(), party, password);
    }

    private ECPublicKey getPublicKey(String party) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return Utils.loadPublicKeyFromKeyStore(getKeyStoreFilePath(), party);
    }

    private static String getKeyStoreFilePath() {
        if(keyStoreFilePath == null) {
            String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
            String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
            keyStoreFilePath = Paths.get(filepath).normalize().toString();
        }
        return keyStoreFilePath;
    }

    private static URL getBaseServerURL() {
        // this URL is just the base URL for the first server, the client increments the port number as needed
        try {
            return new URL("http://localhost:4570");
        } catch(MalformedURLException e) {
            return null;
        }
    }

    private static int getNumberOfServers() {
        return 4;
    }

    private static void launchServers() throws FailedToLoadKeysException {
        new Server(getBaseServerURL().toString(), "Server_1", 4570, 4, "ABCD1").run();
        new Server(getBaseServerURL().toString(), "Server_2", 4571, 4, "ABCD2").run();
        new Server(getBaseServerURL().toString(), "Server_3", 4572, 4, "ABCD3").run();
        new Server(getBaseServerURL().toString(), "Server_4", 4573, 4, "ABCD4").run();
    }

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 4570, 4571, 4572, 4573);

    private MockServerClient mockServerClient;

    /*
    Test if we can register an account using the wrong server public key
     */
    @Test(expected = RegisterException.class)
    public void wrongServerPublicKeyTest() throws RegisterException, FailedToLoadKeysException {
        // TODO this test doesn't make sense anymore as it is, because now we have multiple servers and we no longer specify which server key to use directly to the client
        Main.main(new String[] {"Server_1"});
        Register.main(new String[] {"-n", "Client_1", "-s", "SERVER_KEYS_TEST", "-a", "10"});
    }

    @Test
    public void simpleSendAmountTest() throws Exception {
        launchServers();

        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 10); //Register client1
        String prevHash = getPreviousHash(client, getPublicKey("Client_1"));
        client.register(getPublicKey("Client_2"), getPrivateKey("Client_2"), 40); //Register client2

        client.sendAmount(getPublicKey("Client_1"), getPublicKey("Client_2"), 5, getPrivateKey("Client_1"), prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(getPublicKey("Client_2"));
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, getPublicKey("Client_2"));
        client.receiveAmount(getPublicKey("Client_2"), transaction.source, transaction.amount, getPrivateKey("Client_2"), prevHashClient2, transaction.signature);

        //Validate transfer result
        Serialization.CheckAccountResponse result1 = client.checkAccount(getPublicKey("Client_1"));
        Serialization.CheckAccountResponse result2 = client.checkAccount(getPublicKey("Client_2"));
        assert(result1.balance == 5);
        assert(result2.balance == 45);
    }

    // request

    @Test
    public void testRegisterClient() throws Exception {
        launchServers();
        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );
        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});

        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 234); //Register client1


    }

    @Test (expected = RegisterException.class)
    public void testRegisterTamperingWithRequest() throws Exception {
        launchServers();
        // simulating tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnRequestCallback")
                );



        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});

        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 340); //Register client1
    }


    @Test (expected = SendAmountException.class)
    public void testSendAmountTamperingWithRequest() throws Exception {
        launchServers();
        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        // tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/sendAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnRequestCallback")

                );

        // forward - no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("GET"))
                .forward(
                        forward()
                                .withHost("localhost")
                                .withPort(4567)
                );


        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});
        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 234); //Register client1

        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 1000); //Register client1
        client.register(getPublicKey("Client_2"), getPrivateKey("Client_2"), 40); //Register client2
        String prevHash = getPreviousHash(client, getPublicKey("Client_1"));
        client.sendAmount(getPublicKey("Client_1"), getPublicKey("Client_2"), 30, getPrivateKey("Client_1"), prevHash);
    }


    @Test (expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithRequest() throws Exception {
        launchServers();
        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/sendAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")

                );

        // tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/receiveAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnRequestCallback")

                );

        // forward - no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("GET"))
                .forward(
                        forward()
                                .withHost("localhost")
                                .withPort(4567)
                );


        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});
        URL serverURL = new URL("http://localhost:3456");

        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 1000); //Register client1
        client.register(getPublicKey("Client_2"), getPrivateKey("Client_2"), 40); //Register client2
        String prevHash = getPreviousHash(client, getPublicKey("Client_1"));
        client.sendAmount(getPublicKey("Client_1"), getPublicKey("Client_2"), 30, getPrivateKey("Client_1"), prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(getPublicKey("Client_2"));
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, getPublicKey("Client_2"));
        client.receiveAmount(getPublicKey("Client_2"), transaction.source, transaction.amount, getPrivateKey("Client_2"), prevHashClient2, transaction.signature);

    }



    /// Reponse

    @Test (expected = RegisterException.class)
    public void testRegisterTamperingWithResponse() throws Exception {
        launchServers();

        // simulating tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnResponseCallback")
                );



        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});
        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 340); //Register client1

    }


    @Test (expected = SendAmountException.class)
    public void testSendAmountTamperingWithResponse() throws Exception {
        launchServers();

        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        // tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/sendAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnResponseCallback")

                );

        // forward - no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("GET"))
                .forward(
                        forward()
                                .withHost("localhost")
                                .withPort(4567)
                );


        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});
        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 1000); //Register client1
        client.register(getPublicKey("Client_2"), getPrivateKey("Client_2"), 40); //Register client2
        String prevHash = getPreviousHash(client, getPublicKey("Client_1"));
        client.sendAmount(getPublicKey("Client_1"), getPublicKey("Client_2"), 30, getPrivateKey("Client_1"), prevHash);

    }


    @Test (expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithResponse() throws Exception {
        launchServers();

        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        // no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/sendAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")

                );

        // tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/receiveAmount"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorWithTamperingOnResponseCallback")

                );

        // forward - no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("GET"))
                .forward(
                        forward()
                                .withHost("localhost")
                                .withPort(4567)
                );


        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10", "-p", "3456"});
        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(getPublicKey("Client_1"), getPrivateKey("Client_1"), 1000); //Register client1
        client.register(getPublicKey("Client_2"), getPrivateKey("Client_2"), 40); //Register client2
        String prevHash = getPreviousHash(client, getPublicKey("Client_1"));
        client.sendAmount(getPublicKey("Client_1"), getPublicKey("Client_2"), 30, getPrivateKey("Client_1"), prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(getPublicKey("Client_2"));
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, getPublicKey("Client_2"));
        client.receiveAmount(getPublicKey("Client_2"), transaction.source, transaction.amount, getPrivateKey("Client_2"), prevHashClient2, transaction.signature);

    }
}
