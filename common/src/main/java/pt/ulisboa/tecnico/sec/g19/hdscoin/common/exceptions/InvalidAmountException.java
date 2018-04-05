package pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions;

public class InvalidAmountException extends Exception {

    public InvalidAmountException(String message, int amount) {
        super(message + " Amount: " + amount);
    }
}
