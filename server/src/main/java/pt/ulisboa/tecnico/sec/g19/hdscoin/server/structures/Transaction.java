package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidKeyException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.SignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.InvalidValueException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingLedgerException;

import java.security.KeyException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class Transaction {
    private final static Logger log = Logger.getLogger(Transaction.class.getName());

    public enum TransactionTypes implements TransactionType {SENDING, RECEIVING}

    public enum SpecialTransactionType implements TransactionType {FIRST}

    private int id;
    private Ledger source;
    private Ledger target;
    private int amount;
    private String nonce;
    private String hash;
    private String previousHash;
    private boolean pending;
    private TransactionType type;

    /**
     * @param id
     * @param source
     * @param target
     * @param amount
     * @param nonce
     * @param hash
     * @param previousHash
     * @param type
     */
    private Transaction(int id, Ledger source, Ledger target, int amount, String nonce, String hash, String previousHash, TransactionType type) {
        Utils.initLogger(log);
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

    public Transaction(Connection connection, Ledger source, Ledger target, int amount, String nonce, String hash, String previousHash, TransactionType type)
            throws SQLException, InvalidLedgerException, InvalidAmountException, InvalidValueException, SignatureException {
        this(-1, source, target, amount, nonce, hash, previousHash, type);

        if (type != SpecialTransactionType.FIRST) {    // the first transaction can have null on the previous hash
            if (previousHash == null) {
                throw new InvalidValueException("The previous hash can't be null.");
            }

            // get latest transaction to check if previousSignature is correct
            Transaction latestTransaction = source.getLatestTransaction(connection);

            if (latestTransaction == null) {
                throw new SignatureException("The previous signature does not match the correct one");
            }

            if (latestTransaction == null && !previousHash.isEmpty()) {
                throw new SignatureException("The previous signature is not empty as it should");
            } else if (latestTransaction != null && !previousHash.equals(latestTransaction.getHash())) {
                throw new SignatureException("The previous signature does not match the correct one");
            }
        } else if (previousHash != null && !previousHash.isEmpty()) {
            throw new SignatureException("The previous hash must be null or empty for FIRST transactions");
        }
        if (source == null || target == null) {
            throw new InvalidLedgerException("Both the source and target ledgers can't be null.");
        }
        if (amount < 1) {
            throw new InvalidAmountException("Insufficient amount to create a transaction.", amount);
        }
        if (nonce == null || nonce.isEmpty()) {
            throw new InvalidValueException("The nonce can't be null nor empty.");
        }
        if (hash == null || hash.isEmpty()) {
            throw new InvalidValueException("The hash can't be null nor empty.");
        }
        if (type == null) {
            throw new InvalidValueException("The type of transaction can't be null.");
        }
        setId(getNextId(connection));
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
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

    public void persist(Connection connection) throws SQLException {
        String stmt = "INSERT OR REPLACE INTO tx (id, ledger_id, other_id, is_send, amount, nonce, hash, " +
                "prev_hash, pending) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setInt(1, this.id);
            prepStmt.setInt(2, this.getSourceLedger().getId());
            prepStmt.setInt(3, this.getTargetLedger().getId());
            prepStmt.setInt(4, type == TransactionTypes.SENDING ? 1 : 0);
            prepStmt.setInt(5, this.amount);
            prepStmt.setString(6, this.nonce);
            prepStmt.setString(7, this.hash);
            prepStmt.setString(8, this.previousHash);
            prepStmt.setInt(9, this.pending ? 1 : 0);

            prepStmt.executeUpdate();
            log.log(Level.INFO, "The following transaction was persisted. " + this.toString());
        } finally {
            if(prepStmt != null) {
                prepStmt.close();
            }
        }
    }


    private static int getNextId(Connection connection) throws SQLException {
        int next = 0;
        Statement statement = connection.createStatement();
        ResultSet rs = statement.executeQuery("select max(id) from tx");
        while (rs.next()) {
            next = rs.getInt(1) + 1;
        }
        return next;
    }


    public static List<Transaction> loadResults(Connection connection, PreparedStatement prepStmt) throws SQLException {
        try {
            List<Transaction> ret = new ArrayList<>();
            ResultSet results = prepStmt.executeQuery();
            while (results.next()) {
                int id = results.getInt(1);
                int sourceLedgerIdId = results.getInt(2);
                int targetLedgerId = results.getInt(3);
                TransactionType type = results.getInt(4) == 1 ? TransactionTypes.SENDING : TransactionTypes.RECEIVING;
                int amount = results.getInt(5);
                String nonce = results.getString(6);
                String hash = results.getString(7);
                String previousHash = results.getString(8);
                boolean pending = results.getInt(9) == 1;

                Ledger source = null;
                Ledger target = null;
                try {
                    source = Ledger.load(connection, sourceLedgerIdId);
                    target = Ledger.load(connection, targetLedgerId);
                } catch (MissingLedgerException | KeyException e) {
                    // this can never happen, unless our own database is corrupt
                }

                Transaction tx = new Transaction(id, source, target, amount, nonce, hash, previousHash, type);
                tx.setPending(pending);

                ret.add(tx);
            }
            return ret;
        } finally {
            prepStmt.close();
        }
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("\n-----------------------------\n");
        builder.append("\t\tTransaction\n");
        builder.append("\t\t-----------\n");
        builder.append(getReadableKeysFormat(this.target, this.source));
        builder.append("Amount: ").append(this.amount).append(" HDS Coins\n");
        builder.append("Type: ").append(this.type).append("\n");
        builder.append("State: ").append((this.pending ? "PENDING" : "COMPLETED")).append("\n");
        builder.append("Nonce: ").append(this.nonce).append("\n");
        builder.append("Signature: ").append(this.hash).append("\n");
        builder.append("Signature prev. Transaction: ").append(this.previousHash).append("\n");
        builder.append("-----------------------------");
        return builder.toString();
    }

    private String getReadableKeysFormat(Ledger source, Ledger target) {
        StringBuilder builder = new StringBuilder();
        try {
            builder.append("Source Public Key: ").append(Serialization.publicKeyToBase64(source.getPublicKey())).append("\n");
        } catch (KeyException e) {
            builder.append("Source Public Key: --------------").append("\n");
        }
        try {
            builder.append("Target Public Key: " + Serialization.publicKeyToBase64(target.getPublicKey())).append("\n");
        } catch (KeyException e) {
            builder.append("Target Public Key: --------------").append("\n");
        }
        return builder.toString();
    }
}