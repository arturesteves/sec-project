package pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions;


public class KeyGenerationException extends Exception{
    public KeyGenerationException(String message, Throwable t) {
        super (message, t);
    }

    public KeyGenerationException(String message) {
        super(message);
    }
}