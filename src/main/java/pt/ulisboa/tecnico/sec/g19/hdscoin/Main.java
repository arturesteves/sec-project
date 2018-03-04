package pt.ulisboa.tecnico.sec.g19.hdscoin;

import static spark.Spark.*;

public class Main {

    public static void main(String[] args) {
        System.out.println("Hello World!");
        get("/hello", (req, res) -> "Hello World");
    }
}