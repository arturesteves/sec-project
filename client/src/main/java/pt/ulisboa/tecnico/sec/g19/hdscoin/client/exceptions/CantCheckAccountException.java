package pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions;


public class CantCheckAccountException extends Exception{

    public CantCheckAccountException(String message, Throwable exception) {
        super (message, exception);
    }
}
