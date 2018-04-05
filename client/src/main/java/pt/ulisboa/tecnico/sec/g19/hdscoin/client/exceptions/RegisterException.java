package pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions;


public class RegisterException extends Exception{

    public RegisterException(String message, Throwable t) {
        super (message, t);
    }

    public RegisterException(String message) {
        super (message);
    }
}
