package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.eclipse.jetty.util.log.Log;
import org.mockserver.mock.action.ExpectationCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;

import java.io.IOException;
import java.net.URL;

import static org.mockserver.model.HttpResponse.notFoundResponse;
import static org.mockserver.model.HttpResponse.response;


public class InterceptorWithTamperingOnRequestCallback implements ExpectationCallback {

    public HttpResponse handle(HttpRequest httpRequest) {
        if (httpRequest.getPath().getValue().endsWith("/register")) {
            try {
                URL newURL = new URL("http://" + httpRequest.getHeader("Host").get(0));
                int destPort = newURL.getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));

                Serialization.RegisterRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.RegisterRequest.class);
                req.initialTransaction.nonce = "bananas";

                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(request.body());

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

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.SendAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.SendAmountRequest.class);
                //Spend 20 units more
                req.transaction.amount = req.transaction.amount + 20;
                Log.getLog().warn("SERI: " + Serialization.serialize(req));
                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();

                return response()
                        .withStatusCode(request.code())
                        .withHeader(Serialization.SIGNATURE_HEADER_NAME, responseSignature)
                        .withBody(body);

            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if (httpRequest.getPath().getValue().endsWith("/receiveAmount")) {
            try {
                URL newURL = new URL("http://" + httpRequest.getHeader("Host").get(0));
                int destPort = newURL.getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/receiveAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));

                if (httpRequest.containsHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME)) {
                    request.header(Serialization.ECHO_SIGNATURES_HEADER_NAME,
                            httpRequest.getHeader(Serialization.ECHO_SIGNATURES_HEADER_NAME).get(0));
                }

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.ReceiveAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.ReceiveAmountRequest.class);
                //Spend 20 units more
                req.transaction.amount = req.transaction.amount + 20;

                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);

                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(request.body());

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        return notFoundResponse();
    }

}
