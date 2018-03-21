package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import static spark.Spark.post;
import static spark.Spark.get;

public class Main {

    public static void main(String[] args) {
        post("/register", "application/json", (req, res) -> {

            Serialization.RegisterRequest request = Serialization.parse(req, Serialization.RegisterRequest.class);
            //Todo - Validate data received.
            //Todo - Do Something with the data.
            System.out.println("Received Public key: " + request.key);

            res.status(200);
            return "Success";
        });

        post("/sendAmount", "application/json", (req, res) -> {
            Serialization.SendAmountRequest request = Serialization.parse(req, Serialization.SendAmountRequest.class);

            //Todo - Do Something with the data.
            System.out.println("Received Source Public key: " + request.source);
            System.out.println("Received Source Public key: " + request.destination);
            System.out.println("Received amount: " + request.amount);

            res.status(200);
            return "Success";
        });

        get("/checkAccount/:key", "application/json", (req, res) -> {
            //Todo - Do Something with the data.
            System.out.println("Received account Public key: " + req.params(":key"));

            res.status(200);
            return "Success";
        });

        post("/receiveAmount", "application/json", (req, res) -> {
            Serialization.ReceiveAmountRequest request = Serialization.parse(req, Serialization.ReceiveAmountRequest.class);

            //Todo - Do Something with the data.
            System.out.println("Received Source Public key: " + request.source);

            res.status(200);
            return "Success";
        });

        get("/audit/:key", "application/json", (req, res) -> {
            //Todo - Do Something with the data.
            System.out.println("Received account Public key: " + req.params(":key"));

            res.status(200);
            return "Success";
        });
    }
}