package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.*;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Register;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;

public class TestWebServerTest {

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 9000);

    private MockServerClient mockServerClient;

    @Test
    public void testRegisterClient() throws RegisterException {
        // test inicar sv com uma key e usar outro sv key para ssinar - deve falhar
        mockServerClient.when(HttpRequest.request("/register")).respond(HttpResponse.response().withStatusCode(200));

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
