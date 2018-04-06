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

public class TestWebServerTest {

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, 9000);

    private MockServerClient mockServerClient;

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
