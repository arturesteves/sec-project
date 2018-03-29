package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidValueException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidDatabaseIdException;

public final class Transaction {

    public enum TransactionType {SENDING, RECEIVING}

    private int id;
    private Ledger source;
    private Ledger target;
    private int amount;
    private String nonce;
    private String hash;
    private String previousHash;
    private boolean pending;
    private TransactionType type;


    public Transaction(int id, Ledger source, Ledger target, int amount, String nonce, String hash, String previousHash, TransactionType type) throws InvalidLedgerException, InvalidAmountException, InvalidValueException {
        if (source == null || target == null) {
            throw new InvalidLedgerException("Both the source and target ledgers can't be null.");
        }
        if (amount < 1) {
            throw new InvalidAmountException("Insufficient amount to create a transaction.", amount);
        }
        if (nonce == null) {
            throw new InvalidValueException("The nonce can't be null.");
        }
        if (hash == null || previousHash == null) {
            throw new InvalidValueException("The hash and the previous hash can't be null.");
        }
        if (type == null) {
            throw new InvalidValueException("The type of transaction can't be null.");
        }
        this.id = id;
        this.source = source;
        this.target = target;
        this.amount = amount;
        this.nonce = nonce;
        this.hash = hash;
        this.previousHash = previousHash;
        this.type = type;
        this.pending = true;
    }

    public Transaction(Ledger source, Ledger target, int amount, String nonce, String hash, String previousHash, TransactionType type) throws InvalidLedgerException, InvalidAmountException, InvalidValueException {
        this(-1, source, target, amount, nonce, hash, previousHash, type);
    }


    public int getID() {
        return this.id;
    }

    public void setId(int id) throws InvalidDatabaseIdException {
        if (id > 0) {
            this.id = id;
        }
        throw new InvalidDatabaseIdException("The id has to be a positive integer number.", id);
    }

    public Ledger getSourceLedger() {
        return this.source;
    }

    public Ledger getTargetLedger() {
        return this.target;
    }

    public int getAmount() {
        return this.amount;
    }

    public String getNonce() {
        return this.nonce;
    }

    public String getHash() {
        return this.hash;
    }

    public String getPreviousHash() {
        return this.previousHash;
    }

    public boolean isPending() {
        return this.pending;
    }

    public void setPending(boolean pending) {
        this.pending = pending;
    }

    public TransactionType getTransactionType() {
        return this.type;
    }

}