package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Client;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.ReceiveAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.SendAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Server;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;
import spark.Service;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.mockserver.model.HttpClassCallback.callback;
import static org.mockserver.model.HttpRequest.request;

public class TestMitmTampering {

    private List<Service> serverGroup = new ArrayList();

    @Before
    public void launchServers() throws FailedToLoadKeysException {
        // launch servers on the "wrong" ports. the mocks will listen on the correct ports.
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_1", 5570, 4, "ABCD1").ignite());
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_2", 5571, 4, "ABCD2").ignite());
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_3", 5572, 4, "ABCD3").ignite());
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_4", 5573, 4, "ABCD4").ignite());
    }

    @After
    public void stopServers() {
        for (Service service : serverGroup) {
            service.stop();
        }
        serverGroup.clear();
    }

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 4570, 4571, 4572, 4573);

    private MockServerClient mockServerClient;

    @Test
    public void testRegisterClient() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");

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

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 234); //Register client1
    }

    @Test(expected = RegisterException.class)
    public void testRegisterTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");

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

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 340); //Register client1
    }


    @Test(expected = SendAmountException.class)
    public void testSendAmountTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");
        ECPublicKey client2pubKey = Helpers.getPublicKey("Client_2");
        ECPrivateKey client2privKey = Helpers.getPrivateKey("Client_2");

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
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());

        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = Helpers.getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
    }


    @Test(expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithRequest() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");
        ECPublicKey client2pubKey = Helpers.getPublicKey("Client_2");
        ECPrivateKey client2privKey = Helpers.getPrivateKey("Client_2");

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
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        URL serverURL = new URL("http://localhost:3456");

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = Helpers.getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size() - 1);
        String prevHashClient2 = Helpers.getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

    }


    /// Reponse

    @Test(expected = RegisterException.class)
    public void testRegisterTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");

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

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 340); //Register client1

    }


    @Test(expected = SendAmountException.class)
    public void testSendAmountTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");
        ECPublicKey client2pubKey = Helpers.getPublicKey("Client_2");
        ECPrivateKey client2privKey = Helpers.getPrivateKey("Client_2");

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
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );
        // forward - no tampering
        mockServerClient
                .when(
                        request()
                                .withMethod("POST"))
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = Helpers.getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);

    }


    @Test(expected = ReceiveAmountException.class)
    public void testReceiveAmountTamperingWithResponse() throws Exception {
        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");
        ECPublicKey client2pubKey = Helpers.getPublicKey("Client_2");
        ECPrivateKey client2privKey = Helpers.getPrivateKey("Client_2");

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
                .callback(
                        callback()
                                .withCallbackClass("pt.ulisboa.tecnico.sec.g19.hdscoin.tests.InterceptorCallback")
                );

        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 1000); //Register client1
        client.register(client2pubKey, client2privKey, 40); //Register client2
        String prevHash = Helpers.getPreviousHash(client, client1pubKey);
        client.sendAmount(client1pubKey, client2pubKey, 30, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size() - 1);
        String prevHashClient2 = Helpers.getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

    }
}
