package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;

public class InvalidAmountException extends Exception {

    public InvalidAmountException(String message, double amount) {
        super(message + " Amount: " + amount);
    }
}
