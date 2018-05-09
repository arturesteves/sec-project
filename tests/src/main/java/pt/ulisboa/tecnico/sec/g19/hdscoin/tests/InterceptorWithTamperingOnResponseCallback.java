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


public class InterceptorWithTamperingOnResponseCallback implements ExpectationCallback {

    public HttpResponse handle(HttpRequest httpRequest) {
        if (httpRequest.getPath().getValue().endsWith("/register")) {
            try {

                int destPort = new URL(httpRequest.getPath().getValue()).getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.RegisterRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.RegisterRequest.class);
                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);
                response.nonce = "bananas2";

                //Log.getLog().warn("BODYTESTE: " + body);
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

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.SendAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.SendAmountRequest.class);
                Log.getLog().warn("SERI: " + Serialization.serialize(req));
                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);
                response.nonce = "banana4";

                Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(Serialization.serialize(response));

            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if (httpRequest.getPath().getValue().endsWith("/receiveAmount")) {
            try {
                int destPort = new URL(httpRequest.getPath().getValue()).getPort() + 1000;

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:" + destPort + "/receiveAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.ReceiveAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString(), Serialization.ReceiveAmountRequest.class);
                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);
                response.nonce = "banana4";
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
