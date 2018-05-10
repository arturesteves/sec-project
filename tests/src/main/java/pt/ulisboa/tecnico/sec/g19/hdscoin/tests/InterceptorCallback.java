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
                URL newURL = new URL("http://" + httpRequest.getHeader("Host").get(0));
                int destPort = newURL.getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                request.send(httpRequest.getBody().getValue().toString().getBytes());

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();

                Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader(Serialization.SIGNATURE_HEADER_NAME, responseSignature)
                        .withBody(body);

            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if (httpRequest.getPath().getValue().endsWith("/sendAmount")) {
            try {
                URL newURL = new URL("http://" + httpRequest.getHeader("Host").get(0));
                int destPort = newURL.getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/sendAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                if (httpRequest.containsHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME)) {
                    request.header(Serialization.ECHO_SIGNATURES_HEADER_NAME,
                            httpRequest.getHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME).get(0));
                }
                request.send(httpRequest.getBody().getValue().toString().getBytes());

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();

                Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader(Serialization.SIGNATURE_HEADER_NAME, responseSignature)
                        .withBody(body);

            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                URL newURL = new URL("http://" + httpRequest.getHeader("Host").get(0));
                newURL = new URL("http", newURL.getHost(), newURL.getPort() + 1000, httpRequest.getPath().getValue());

                com.github.kevinsawicki.http.HttpRequest request;
                if (httpRequest.getMethod().getValue().equals("POST")) {
                    request = com.github.kevinsawicki.http.HttpRequest.post(newURL);
                } else {
                    request = com.github.kevinsawicki.http.HttpRequest.get(newURL);
                }

                if (httpRequest.containsHeader(Serialization.SIGNATURE_HEADER_NAME)) {
                    request.header(Serialization.SIGNATURE_HEADER_NAME,
                            httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                }
                if (httpRequest.containsHeader(Serialization.NONCE_HEADER_NAME)) {
                    request.header(Serialization.NONCE_HEADER_NAME,
                            httpRequest.getHeader(Serialization.NONCE_HEADER_NAME).get(0));
                }
                if (httpRequest.containsHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME)) {
                    request.header(Serialization.ECHO_SIGNATURES_HEADER_NAME,
                            httpRequest.getHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME).get(0));
                }

                if (httpRequest.getMethod().getValue().equals("POST")) {
                    request.send(httpRequest.getBody().getValue().toString().getBytes());
                }

                String body = request.body();
                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);

                HttpResponse response = response()
                        .withStatusCode(request.code())
                        .withBody(body);

                if (responseSignature != null) {
                    response = response.withHeader(Serialization.SIGNATURE_HEADER_NAME, responseSignature);
                }

                return response;

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return notFoundResponse();
    }

}
