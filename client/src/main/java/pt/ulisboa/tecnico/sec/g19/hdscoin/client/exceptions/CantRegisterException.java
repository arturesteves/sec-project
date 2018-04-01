package pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions;


public class CantRegisterException extends Exception{

    public CantRegisterException(String message, Throwable exception) {
        super (message, exception);
    }
}
