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
import spark.Service;

import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TestWebServerTest {
    private static int count = 0;

    private List<Service> serverGroup = new ArrayList();

    private String keyStoreFilePath = null;

    private String getPreviousHash(Client client, ECPublicKey clientPublicKey) throws AuditException {
        Serialization.AuditResponse transactionsClient1 = client.audit(clientPublicKey);
        return transactionsClient1.ledger.transactions.get(transactionsClient1.ledger.transactions.size() - 1).signature;
    }

    private ECPrivateKey getPrivateKey(String party) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        String password = "abc";
        if (party.startsWith("Server_")) {
            int serverNum = Integer.parseInt(party.substring("Server_".length()));
            password = "ABCD" + Integer.toString(serverNum);
        }

        return Utils.loadPrivateKeyFromKeyStore(getKeyStoreFilePath(), party, password);
    }

    private ECPublicKey getPublicKey(String party) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return Utils.loadPublicKeyFromKeyStore(getKeyStoreFilePath(), party);
    }

    private String getKeyStoreFilePath() {
        return keyStoreFilePath;
    }

    private static URL getBaseServerURL() {
        // this URL is just the base URL for the first server, the client increments the port number as needed
        try {
            return new URL("http://localhost:4570");
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static int getNumberOfServers() {
        return 4;
    }

    @Before
    public void loadKeyStoreFilePath() {
        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        keyStoreFilePath = Paths.get(filepath).normalize().toString();
    }

    @Before
    public void launchServers() throws FailedToLoadKeysException {
        serverGroup.add(new Server(getBaseServerURL().toString(), "Server_1", 4570, 4, "ABCD1").ignite());
        serverGroup.add(new Server(getBaseServerURL().toString(), "Server_2", 4571, 4, "ABCD2").ignite());
        serverGroup.add(new Server(getBaseServerURL().toString(), "Server_3", 4572, 4, "ABCD3").ignite());
        serverGroup.add(new Server(getBaseServerURL().toString(), "Server_4", 4573, 4, "ABCD4").ignite());
    }

    @After
    public void stopServers() {
        for (Service service : serverGroup) {
            service.stop();
        }
        serverGroup.clear();
    }

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 5570, 5571, 5572, 5573);

    private MockServerClient mockServerClient;

    /*
    Test if we can register an account using the wrong server public key
     */
    /*@Test(expected = RegisterException.class)
    public void wrongServerPublicKeyTest() throws RegisterException, FailedToLoadKeysException {
        // TODO this test doesn't make sense anymore as it is, because now we have multiple servers and we no longer specify which server key to use directly to the client
        Main.main(new String[] {"Server_1"});
        Register.main(new String[] {"-n", "Client_1", "-s", "SERVER_KEYS_TEST", "-a", "10"});
    }*/

    @Test
    public void simpleSendAmountTest() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");
        ECPublicKey client2pubKey = getPublicKey("Client_2");
        ECPrivateKey client2privKey = getPrivateKey("Client_2");
        Client client = new Client(getBaseServerURL(), getNumberOfServers(), getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 10); //Register client1
        String prevHash = getPreviousHash(client, client1pubKey);
        client.register(client2pubKey, client2privKey, 40); //Register client2

        client.sendAmount(client1pubKey, client2pubKey, 5, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size() - 1);
        String prevHashClient2 = getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

        //Validate transfer result
        Serialization.CheckAccountResponse result1 = client.checkAccount(client1pubKey);
        Serialization.CheckAccountResponse result2 = client.checkAccount(client2pubKey);
        assert (result1.balance == 5);
        assert (result2.balance == 45);
    }

    // request

    @Test
    public void testRegisterClient() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");

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
        client.register(client1pubKey, client1privKey, 234); //Register client1


    }

    @Test (expected = RegisterException.class)
    public void testRegisterTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");

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
        client.register(client1pubKey, client1privKey, 340); //Register client1
    }


    @Test (expected = SendAmountException.class)
    public void testSendAmountTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");
        ECPublicKey client2pubKey = getPublicKey("Client_2");
        ECPrivateKey client2privKey = getPrivateKey("Client_2");

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
        client.register(client1pubKey, client1privKey, 234); //Register client1

        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
    }


    @Test (expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");
        ECPublicKey client2pubKey = getPublicKey("Client_2");
        ECPrivateKey client2privKey = getPrivateKey("Client_2");

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
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

    }



    /// Reponse

    @Test (expected = RegisterException.class)
    public void testRegisterTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");

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
        client.register(client1pubKey, client1privKey, 340); //Register client1

    }


    @Test (expected = SendAmountException.class)
    public void testSendAmountTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");
        ECPublicKey client2pubKey = getPublicKey("Client_2");
        ECPrivateKey client2privKey = getPrivateKey("Client_2");

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
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);

    }


    @Test (expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = getPublicKey("Client_1");
        ECPrivateKey client1privKey = getPrivateKey("Client_1");
        ECPublicKey client2pubKey = getPublicKey("Client_2");
        ECPrivateKey client2privKey = getPrivateKey("Client_2");

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
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

    }
}
