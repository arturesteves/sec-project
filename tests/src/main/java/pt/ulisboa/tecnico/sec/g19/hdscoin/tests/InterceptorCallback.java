package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Client;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Transaction;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.mockserver.model.HttpResponse.notFoundResponse;
import static org.mockserver.model.HttpResponse.response;


public class InterceptorCallback implements ExpectationCallback {

    public HttpResponse handle(HttpRequest httpRequest) {
        if (httpRequest.getPath().getValue().endsWith("/register")) {
            try {

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:4567/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                request.send(Serialization.serialize(httpRequest.getBody()));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                Serialization.Response response = Serialization.parse(request.body(), Serialization.Response.class);

                System.out.println("BODY: " + request.body());
                return response()
                        .withStatusCode(200)
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(Serialization.serialize(response));

            } catch (IOException e) {
                e.printStackTrace();
            }



            return httpResponse;
        } else {
            return notFoundResponse();
        }
    }

    public static HttpResponse httpResponse = response()
            .withStatusCode(200)
            .withHeader("SIGNATURE", "MEUCIC/m/0b8EHyAcuhmdyE+CQr03jL6kgBfHDfETETzxL1XAiEAgqZHB4cqMjUtKbOChZMijjj33HdSxU6YQ3G/I0BjfcA=")
            .withBody("{\n" +
                    "    \"statusCode\": 400,\n" +
                    "    \"status\": \"ERROR_NO_SIGNATURE_MATCH\",\n" +
                    "    \"nonce\": \"abc\"\n" +
                    "}");
            /*.withBody("{\n" +
                    "\t\"initialTransaction\": \n" +
                    "\t{\n" +
                    "\t\t\"source\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEba/fCx1A3jn0wa7tupGBoCPqJvXvbCyqtaFmvXZXkoUklrc9jCenyveUamhC0ZH3Ne1roZWL+MTCZ9lpOMhHnQ==\",\n" +
                    "\t\t\"target\": \"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEba/fCx1A3jn0wa7tupGBoCPqJvXvbCyqtaFmvXZXkoUklrc9jCenyveUamhC0ZH3Ne1roZWL+MTCZ9lpOMhHnQ==\",\n" +
                    "\t\t\"isSend\": \"true\",\n" +
                    "\t\t\"amount\": 15,\n" +
                    "\t\t\"nonce\" : \"abc\",\n" +
                    "\t    \"previousSignature\": \"MEQCIGWVj8dH6aeAqvUOgUnHhXRWDBgLYr5Ub57mm6AqGvaGAiAdNMZfyWkuGNpAjFiNhGX+voSN7MQ29d0hs0rKsSo/ZQ==\",\n" +
                    "\t    \"signature\": \"MEQCIGWVj8dH6aeAqvUOgUnHhXRWDBgLYr5Ub57mm6AqGvaGAiAdNMZfyWkuGNpAjFiNhGX+voSN7MQ29d0hs0rKsSo/ZQ==\"\n" +
                    "\t}\n" +
                    "}");
                    */
}
