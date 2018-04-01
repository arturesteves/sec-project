package pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions;


public class InvalidClientSignatureException extends Exception{

    public InvalidClientSignatureException (String message) {
        super (message);
    }
}
