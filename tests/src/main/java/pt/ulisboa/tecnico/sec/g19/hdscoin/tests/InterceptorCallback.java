package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.eclipse.jetty.util.log.Log;
import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Client;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Transaction;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
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
                int destPort = new URL(httpRequest.getPath().getValue()).getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                request.send(httpRequest.getBody().getValue().toString().getBytes());

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);

                Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(Serialization.serialize(response));

            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if (httpRequest.getPath().getValue().endsWith("/sendAmount")) {
            try {
                int destPort = new URL(httpRequest.getPath().getValue()).getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/sendAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                request.send(httpRequest.getBody().getValue().toString().getBytes());

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);

                Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(Serialization.serialize(response));

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return notFoundResponse();
    }

}
