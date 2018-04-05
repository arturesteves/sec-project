package pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions;

public class InvalidKeyException extends Exception {

    public InvalidKeyException (String message, Throwable t) {
        super (message, t);
    }

    public InvalidKeyException (String message) {
        super (message);
    }
}
