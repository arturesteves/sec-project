package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidKeyException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidDatabaseId; 
import java.security.interfaces.ECPublicKey;


public final class Ledger {

    private int id;
    private ECPublicKey publicKey;    // can't change
    private double amount;


    public Ledger (int id, ECPublicKey publicKey, double amount) throws InvalidKeyException, InvalidAmountException{
        if (publicKey == null) {
            throw new InvalidKeyException ("Null key when trying to initialize a ledger.");
        }
        if (amount < 0.1) {
            throw new InvalidAmountException ("Insufficient amount to setup a ledger.", amount);
        }
        this.publicKey = publicKey;
        this.amount = amount;
        this.id = id;
    }

    public Ledger (ECPublicKey publicKey, double amount) throws InvalidKeyException, InvalidAmountException{
        this (-1, publicKey, amount);    
    }

    public int getID () {
        return this.id;
    }

    public void setId (int id) throws InvalidDatabaseId{
        if (id > 0) {
            this.id = id;
        }
        throw new InvalidDatabaseId ("The id has to be a positive integer number.", id);
    }

    public ECPublicKey getPublicKey () {
        return this.publicKey;
    }

    public double getAmount () {
        return this.amount;
    }

    public void setAmount (double amount) throws InvalidAmountException{
        if (amount >= 0.0) {
            this.amount = amount;
        }
        throw new InvalidAmountException ("The balance of the ledger can't be negative.", amount);
    }
    
}