package pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions;


public class CantRegisterException extends Exception{

    public CantRegisterException(String message, Throwable t) {
        super (message, t);
    }

    public CantRegisterException(String message) {
        super (message);
    }
}
