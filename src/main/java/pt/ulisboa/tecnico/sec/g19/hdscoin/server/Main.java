package pt.ulisboa.tecnico.sec.g19.hdscoin.server;
import static spark.Spark.get;
import static spark.Spark.post;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.logging.ConsoleHandler;

public class Main {

    private static final Gson GSON = new Gson();


    private static Map<String, Object> parseBody(String body) {
        Type type = new TypeToken<Map<String, Object>>(){}.getType();
        return GSON.fromJson(body, type);
    }

    public static void main(String[] args) {

        post("/register", "application/json", (req, res) -> {

            Map<String, Object> bodyMap = Main.parseBody(req.body());
            //Todo - Validate data received.
            //Todo - Do Something with the data.
            System.out.println("Received Public key: " + (String)bodyMap.get("key"));


            res.status(200);
            return "Success";

        });

        post("/sendAmount", "application/json", (req, res) -> {

            Map<String, Object> bodyMap = Main.parseBody(req.body());

            //Todo - Do Something with the data.
            System.out.println("Received Source Public key: " + (String)bodyMap.get("source"));
            System.out.println("Received Source Public key: " + (String)bodyMap.get("destination"));
            System.out.println("Received amount: " + ((Double)bodyMap.get("amount")).intValue());

            res.status(200);
            return "Success";

        });

        get("/checkAccount:key", "application/json", (req, res) -> {

            //Todo - Do Something with the data.
            System.out.println("Received account Public key: " + req.params(":name"));

            res.status(200);
            return "Success";

        });





    }
}