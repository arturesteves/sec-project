package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.model.HttpError;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Client;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Server;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;
import spark.Service;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockserver.model.HttpRequest.request;

public class TestByzantine {
    private List<Service> serverGroup = new ArrayList();

    @Before
    public void launchServers() throws FailedToLoadKeysException {
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_1", 4570, 4, "ABCD1").ignite());
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_2", 4571, 4, "ABCD2").ignite());
        serverGroup.add(new Server(Helpers.getBaseServerURL().toString(), "Server_3", 4572, 4, "ABCD3").ignite());
        // this server is going to have the mock server in between:
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
    public MockServerRule mockServerRule = new MockServerRule(this, 4573);

    private MockServerClient mockServerClient;

    @Test
    public void simpleDropTest() throws Exception {
        // drop all messages to the 4th server as if it was down
        mockServerClient
                .when(request())
                .error(HttpError.error().withDropConnection(true));

        ECPublicKey client1pubKey = Helpers.getPublicKey("Client_1");
        ECPrivateKey client1privKey = Helpers.getPrivateKey("Client_1");
        ECPublicKey client2pubKey = Helpers.getPublicKey("Client_2");
        ECPrivateKey client2privKey = Helpers.getPrivateKey("Client_2");
        Client client = new Client(Helpers.getBaseServerURL(), Helpers.getNumberOfServers(), Helpers.getKeyStoreFilePath());
        client.register(client1pubKey, client1privKey, 10); //Register client1
        String prevHash = Helpers.getPreviousHash(client, client1pubKey);
        client.register(client2pubKey, client2privKey, 40); //Register client2

        client.sendAmount(client1pubKey, client2pubKey, 5, client1privKey, prevHash);
        Serialization.CheckAccountResponse result0 = client.checkAccount(client2pubKey);
        Serialization.Transaction transaction = result0.pendingTransactions.get(result0.pendingTransactions.size() - 1);
        String prevHashClient2 = Helpers.getPreviousHash(client, client2pubKey);
        client.receiveAmount(client2pubKey, transaction.source, transaction.amount, client2privKey, prevHashClient2, transaction.signature);

        //Validate transfer result
        Serialization.CheckAccountResponse result1 = client.checkAccount(client1pubKey);
        Serialization.CheckAccountResponse result2 = client.checkAccount(client2pubKey);
        Serialization.AuditResponse result3 = client.audit(client1pubKey);
        assertEquals(5, result1.balance);
        assertEquals(45, result2.balance);
        assertEquals(2, result3.ledger.transactions.size());
    }
}
