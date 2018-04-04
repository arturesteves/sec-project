package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;


public class SignatureException extends Exception{
    public SignatureException(String message, Throwable t) {
        super (message, t);
    }
}
