package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.*;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;

import org.mockserver.model.HttpTemplate;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import org.mockserver.model.HttpResponse;
import org.mockserver.model.HttpTemplate;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Register;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Main;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;

import static org.mockserver.model.HttpForward.forward;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import static org.mockserver.model.HttpTemplate.template;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Main;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class TestWebServerTest {

    private class Bundle {
        //Client1
        ECPublicKey PublicKeyClient1;
        ECPrivateKey PrivateKeyClient1;
        //Client2
        ECPublicKey PublicKeyClient2;
        ECPrivateKey PrivateKeyClient2;
        //Server
        ECPublicKey PublicKeyServer;

        Bundle(ECPublicKey PublicKeyClient1, ECPrivateKey PrivateKeyClient1,
               ECPublicKey PublicKeyClient2, ECPrivateKey PrivateKeyClient2,
               ECPublicKey PublicKeyServer) {
            this.PublicKeyClient1 = PublicKeyClient1;
            this.PrivateKeyClient1 = PrivateKeyClient1;
            this.PublicKeyClient2 = PublicKeyClient2;
            this.PrivateKeyClient2 = PrivateKeyClient2;
            this.PublicKeyServer = PublicKeyServer;
        }
    }

    private String getPreviousHash(Client client, ECPublicKey clientPublicKey) throws AuditException {
        List<Serialization.Transaction> transactionsClient1 =  client.audit(clientPublicKey);
        return transactionsClient1.get(transactionsClient1.size() - 1).signature;
    }

    private Bundle createTestBundle(String client1, String client2, String server) throws KeyException, IOException {
        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\client";
        String client1KeyFilepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + client1 + ".keys";
        Path client1KeyPath = Paths.get(client1KeyFilepath).normalize(); // create path and normalize it
        String client2KeyFilepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + client2 + ".keys";
        Path client2KeyPath = Paths.get(client2KeyFilepath).normalize(); // create path and normalize it
        String serverKeyFilepath = root + "\\..\\server\\" + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + server + ".keys";
        Path serverKeyPath = Paths.get(serverKeyFilepath).normalize(); // create path and normalize it

        ECPublicKey client1Publickey = Utils.readPublicKeyFromFile(client1KeyPath.toString());
        ECPrivateKey client1Privatekey = Utils.readPrivateKeyFromFile(client1KeyPath.toString());
        ECPublicKey client2Publickey = Utils.readPublicKeyFromFile(client2KeyPath.toString());
        ECPrivateKey client2Privatekey = Utils.readPrivateKeyFromFile(client2KeyPath.toString());
        ECPublicKey serverPublicKey = Utils.readPublicKeyFromFile(serverKeyPath.toString());
        return new Bundle(client1Publickey, client1Privatekey, client2Publickey, client2Privatekey, serverPublicKey);
    }

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 3456);

    private MockServerClient mockServerClient;

    /*
    Test if we can register an account using the wrong server public key
     */
    @Test(expected = RegisterException.class)
    public void wrongServerPublicKeyTest() throws RegisterException, FailedToLoadKeysException {
        Main.main(new String[] {"Server_1"});
        Register.main(new String[] {"-n", "Client_1", "-s", "SERVER_KEYS_TEST", "-a", "10"});
    }

    @Test
    public void simpleSendAmountTest() throws RegisterException,
            FailedToLoadKeysException, SendAmountException,
            KeyException, IOException, AuditException, CheckAccountException, ReceiveAmountException {
        Main.main(new String[] {"Server_1"});
        URL serverURL = new URL("http://localhost:4567");
        Bundle bundle = createTestBundle("Client_1", "Client_2", "Server_1");

        Client client = new Client(serverURL, bundle.PublicKeyServer);
        client.register(bundle.PublicKeyClient1, bundle.PrivateKeyClient1, 10); //Register client1
        String prevHash = getPreviousHash(client, bundle.PublicKeyClient1);
        client.register(bundle.PublicKeyClient2, bundle.PrivateKeyClient2, 40); //Register client2

        client.sendAmount(bundle.PublicKeyClient1, bundle.PublicKeyClient2, 5, bundle.PrivateKeyClient1, prevHash);
        CheckAccountResult result0 = client.checkAccount(bundle.PublicKeyClient2);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size()-1);
        String prevHashClient2 = getPreviousHash(client, bundle.PublicKeyClient2);
        client.receiveAmount(bundle.PublicKeyClient2, transaction.source, transaction.amount, bundle.PrivateKeyClient2, prevHashClient2, transaction.signature);

        //Validate transfer result
        CheckAccountResult result1 = client.checkAccount(bundle.PublicKeyClient1);
        CheckAccountResult result2 = client.checkAccount(bundle.PublicKeyClient2);
        assert(result1.balance == 5);
        assert(result2.balance == 45);
    }








    @Test
    public void testRegisterClient() throws RegisterException, FailedToLoadKeysException {
        Main.main(new String[] {"Server_1"});

        // test inicar sv com uma key e usar outro sv key para ssinar - deve falhar
        //mockServerClient.when(HttpRequest.request("/register")).respond(HttpResponse.response().withStatusCode(200));

        // request.queryStringParameters['userId'] returns an array of values because headers and queryStringParameters have multiple values
        String template = "return {\n" +
                "    'path' : \"/register\",\n" +
                "    'headers' : {\n" +
                "        'Host' : [ \"localhost:4567\" ]\n" +
                "    },\n" +
                "    'body': JSON.stringify(" +
                "{" +
                    "'initialTransaction': " +
                    "{" +
                        "'source': 'a', " +
                        "'target': 'a', " +
                        "'isSend' : true, " +
                        "'amount' : 15, " +
                        "'nonce' : 'abc', " +
                        "'previousSignature': 'a', " +
                        "'signature': 'a'" +
                    "}" +
                "})" +
                "};";

        mockServerClient
                .when(
                        request()
                                .withMethod("POST")
                                .withPath("/register"))
                .forward(
                        template(
                                HttpTemplate.TemplateType.JAVASCRIPT,
                                template)
                );
        Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10"});
        /*


                forward()
                                .withHost("mock-server.com")
                                .withPort(80)
        )*/
                /*
                .respond(
                        response()
                                .withStatusCode(401)
                                .withHeaders(
                                        new Header("Content-Type", "application/json; charset=utf-8"),
                                        new Header("Cache-Control", "public, max-age=86400"))
                                .withBody("{ message: 'incorrect username and password combination' }")
                                .withDelay(TimeUnit.SECONDS,1)
                */

        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10"});

        //Register.main(new String[] {"-n", "Client_1", "-s", "SERVER_KEYS_TEST", "-a", "10"});
    }

    /*
    @Test
    public void testTamperedNonce() throws KeyGenerationException, RegisterException {
        GenerateKeyPair.main(new String[] {"-n", "CLIENT_TAMPERED"});
        Register.main(new String[] {"-n", "CLIENT_TAMPERED", "-s", "SERVER_KEYS_TEST", "-a", "10"});

    }
*/
}
