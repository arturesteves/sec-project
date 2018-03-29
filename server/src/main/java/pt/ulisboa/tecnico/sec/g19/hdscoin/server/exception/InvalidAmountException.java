package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception;

public class InvalidAmountException extends Exception {

    public InvalidAmountException (String message, double amount) {
        super (message + " Amount: " + amount);
    }
}
