package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.*;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.integration.ClientAndProxy;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.junit.MockServerRule;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.GenerateKeyPair;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Register;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.RegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Main;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;

import static org.mockserver.integration.ClientAndProxy.startClientAndProxy;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class TestWebServerTest {


    @BeforeClass
    public static void setup() throws FailedToLoadKeysException {
        // create our srver
        //Main.main(new String[] {"SERVER_KEYS_TEST"});

//        new MockServerClient("localhost", 1080)
//                .when(
//                        request()
//                                .withMethod("POST")
//                                .withPath("/login")
//                                .withBody("{username: 'foo', password: 'bar'}")
//                )
//                .respond(
//                        response()
//                                .withStatusCode(302)
//                                .withCookie(
//                                        "sessionId", "2By8LOhBmaW5nZXJwcmludCIlMDAzMW"
//                                )
//                                .withHeader(
//                                        "Location", "https://www.mock-server.com"
//                                )
//                );
    }

    @Test
    public void testRegisterClient() throws RegisterException {
        // test inicar sv com uma key e usar outro sv key para ssinar - deve falhar
        //Register.main(new String[] {"-n", "Client_1", "-s", "Server_1", "-a", "10"});

        Register.main(new String[] {"-n", "Client_1", "-s", "SERVER_KEYS_TEST", "-a", "10"});

    }

    @Test
    public void testTamperedNonce() throws KeyGenerationException, RegisterException {
        GenerateKeyPair.main(new String[] {"-n", "CLIENT_TAMPERED"});
        Register.main(new String[] {"-n", "Client_2", "-s", "CLIENT_TAMPERED", "-a", "10"});

    }

}
