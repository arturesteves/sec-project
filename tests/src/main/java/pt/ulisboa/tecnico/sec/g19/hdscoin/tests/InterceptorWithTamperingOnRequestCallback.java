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

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:4567/register"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.RegisterRequest req = Serialization.parse(httpRequest.getBody().getValue().toString() , Serialization.RegisterRequest.class);
                req.initialTransaction.nonce  = "bananas";

                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);

                //Log.getLog().warn("BODYTESTE: " + body);
                return response()
                        .withStatusCode(request.code())
                        .withHeader("SIGNATURE", responseSignature)
                        .withBody(Serialization.serialize(response));

            } catch (IOException e) {
                e.printStackTrace();
            }

        } else if(httpRequest.getPath().getValue().endsWith("/sendAmount")) {

            try {

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:4567/sendAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));

                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.SendAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString() , Serialization.SendAmountRequest.class);
                //Spend 20 units more
                req.amount  = req.amount + 20;
                Log.getLog().warn("SERI: " + Serialization.serialize(req));
                request.send(Serialization.serialize(req));

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

        } else if(httpRequest.getPath().getValue().endsWith("/receiveAmount")) {
            try {

                com.github.kevinsawicki.http.HttpRequest request = com.github.kevinsawicki.http.HttpRequest
                        .post(new URL("http://localhost:4567/receiveAmount"));

                request.header(Serialization.SIGNATURE_HEADER_NAME,
                        httpRequest.getHeader(Serialization.SIGNATURE_HEADER_NAME).get(0));
                //httpRequest.getBody().getValue().toString().getBytes();
                Serialization.ReceiveAmountRequest req = Serialization.parse(httpRequest.getBody().getValue().toString() , Serialization.ReceiveAmountRequest.class);
                //Spend 20 units more
                req.transaction.amount  = req.transaction.amount + 20;

                request.send(Serialization.serialize(req));

                String responseSignature = request.header(Serialization.SIGNATURE_HEADER_NAME);
                String body = request.body();
                Serialization.Response response = Serialization.parse(body, Serialization.Response.class);

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
