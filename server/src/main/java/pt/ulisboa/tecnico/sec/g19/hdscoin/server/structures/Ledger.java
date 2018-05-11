package pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


public final class Ledger {
//    public static Logger log;

    private int id;
    private ECPublicKey publicKey;    // can't change
    private int amount;
    private int timestamp;

    private Ledger(int id, ECPublicKey publicKey, int amount, int timestamp) {
        this.publicKey = publicKey;
        this.amount = amount;
        this.id = id;
        this.timestamp = timestamp;
    }

    public Ledger(Connection connection, ECPublicKey publicKey, Serialization.Transaction initialTransaction) throws KeyException, SQLException,
            InvalidValueException, InvalidAmountException, InvalidLedgerException, SignatureException {
        this(-1, publicKey, initialTransaction.amount, 0);
        if (publicKey == null) {
//            log.log(Level.WARNING, "Null key when trying to initialize a ledger.");
            throw new InvalidKeyException("Null key when trying to initialize a ledger.");
        }

        // check if a ledger with this public key already exists. If yes, this ledger can't be created
        try {
            load(connection, publicKey);
//            log.log(Level.WARNING, "A ledger with this public key already exists.");
            throw new InvalidLedgerException("A ledger with this public key already exists.");
        } catch (MissingLedgerException ex) {
            // it's ok, go on
        } catch (KeyException e) {
            throw new InvalidKeyException(e);
        }

        if (amount < 1) {
//            log.log(Level.WARNING, "Insufficient amount to setup a ledger.");
            throw new InvalidAmountException("Insufficient amount to setup a ledger.", amount);
        }
        // generate new ID for ledger based on highest ID in the database
        setId(getNextId(connection));

        storeFirstTransaction(connection, initialTransaction);
//        log.log(Level.INFO, "The first transaction was generated to the ledger with the following " +
//                "public key base 64: " + Serialization.publicKeyToBase64(publicKey));
    }

    public int getId() {
        return this.id;
    }

    private void setId(int id) {
        this.id = id;
    }

    public ECPublicKey getPublicKey() {
        return this.publicKey;
    }

    public int getAmount() {
        return this.amount;
    }

    public void setAmount(int amount) throws InvalidAmountException {
        if (amount < 0) {
            throw new InvalidAmountException("The balance of the ledger can't be negative.", amount);
        }
        this.amount = amount;
    }

    public int getTimestamp () {
        return this.timestamp;
    }

    public void setTimestamp(int newTimestamp) {
        this.timestamp = newTimestamp;
    }

    public void persist(Connection connection) throws SQLException, KeyException {
        String stmt = "INSERT OR REPLACE INTO ledger (id, public_key, balance, timestamp) VALUES (?, ?, ?, ?)";

        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setInt(1, getId());
        prepStmt.setString(2, Serialization.publicKeyToBase64(getPublicKey()));
        prepStmt.setInt(3, getAmount());
        prepStmt.setInt (4, getTimestamp ());
        prepStmt.executeUpdate();
//        log.log(Level.INFO, "A ledger was persisted. Public key of that ledger: " + Serialization.publicKeyToBase64(getPublicKey()));
    }

    // useful for the audit
    public List<Transaction> getAllTransactions(Connection connection) throws SQLException, KeyException {
        String stmt = "SELECT * FROM tx AS t " +
                "JOIN ledger AS l ON t.ledger_id = l.id " +
                "WHERE l.public_key = ? " +
                "ORDER BY t.id";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setString(1, Serialization.publicKeyToBase64(publicKey));

            return Transaction.loadResults(connection, prepStmt);
        } finally {
            if(prepStmt != null) {
                prepStmt.close();
            }
        }
    }

    // useful for the check account
    // get pending transactions where this ledger can receive money
    public List<Transaction> getPendingTransactions(Connection connection, ECPublicKey publicKey)
            throws SQLException, KeyException {
        String stmt = "SELECT * FROM tx AS t " +
                "JOIN ledger AS l ON t.other_id = l.id " +
                "WHERE l.public_key = ? " +
                "AND t.pending = 1";
        PreparedStatement prepStmt = connection.prepareStatement(stmt);
        prepStmt.setString(1, Serialization.publicKeyToBase64(publicKey));

        return Transaction.loadResults(connection, prepStmt);
    }

    public Transaction getLatestTransaction(Connection connection) throws SQLException {
        int latestId = getHighestTransactionId(connection);
        String stmt = "SELECT * FROM tx AS t " +
                "JOIN ledger AS l ON t.ledger_id = ? " +
                "WHERE t.id = ?";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setInt(1, id);
            prepStmt.setInt(2, latestId);

            List<Transaction> results = Transaction.loadResults(connection, prepStmt);
            if (results.size() > 0) {
                return results.get(0);
            }
            return null;
        } finally {
            if (prepStmt != null)
                prepStmt.close();
        }
    }

    private void storeFirstTransaction(Connection connection, Serialization.Transaction tx) throws InvalidLedgerException,
            InvalidAmountException, InvalidValueException, KeyException, SignatureException, SQLException {
        String base64PublicKey = Serialization.publicKeyToBase64(this.publicKey);

        if (!base64PublicKey.equals(tx.source) || !base64PublicKey.equals(tx.target)) {
            throw new InvalidLedgerException("Invalid initial transaction, source and target must be the same " +
                    "and match the server");
        }

        if (tx.previousSignature != null && !tx.previousSignature.isEmpty()) {
            throw new InvalidLedgerException("Invalid initial transaction, must not have previous signature");
        }

        if (tx.isSend) {
            throw new InvalidLedgerException("Invalid initial transaction, must not be sending transaction");
        }

        Transaction dbTx = new Transaction(connection, this, this, this.amount, tx.nonce,
                tx.signature, null, Transaction.SpecialTransactionType.FIRST);
        dbTx.setPending(false);   // is not pending

        dbTx.persist(connection);
    }

    public static Ledger load(Connection connection, int id) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger WHERE id = ?";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setInt(1, id);

            List<Ledger> results = loadResults(prepStmt);
            if (results.size() == 0) {
                throw new MissingLedgerException("A ledger with the specified ID was not found");
            }
            return results.get(0);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
    }

    public static Ledger load(Connection connection, ECPublicKey pk) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger WHERE public_key = ?";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setString(1, Serialization.publicKeyToBase64(pk));

            List<Ledger> results = loadResults(prepStmt);
            if (results.size() == 0) {
//                log.log(Level.WARNING, "A ledger with the specified public key was not found. Public Key: " + pk);
                throw new MissingLedgerException("A ledger with the specified public key was not found.");
            }
            return results.get(0);
        } finally {
            prepStmt.close();
        }
    }

    public static List<Ledger> loadAll(Connection connection) throws SQLException, KeyException, MissingLedgerException {
        String stmt = "SELECT * FROM ledger";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);

            return loadResults(prepStmt);
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
    }

    private static List<Ledger> loadResults(PreparedStatement prepStmt) throws SQLException, KeyException {
        List<Ledger> ret = new ArrayList<>();
        ResultSet results = prepStmt.executeQuery();
        while (results.next()) {
            int id = results.getInt(1);
            ECPublicKey pk = Serialization.base64toPublicKey(results.getString(2));
            int amount = results.getInt(3);
            int timestamp = results.getInt(4);
            ret.add(new Ledger(id, pk, amount, timestamp));
        }
        return ret;
    }

    private int getHighestTransactionId(Connection connection) throws SQLException {
        String stmt = "select max(id) from tx where ledger_id = ?";
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(stmt);
            prepStmt.setInt(1, id);
            ResultSet rs = prepStmt.executeQuery();

            while (rs.next()) {
                return rs.getInt(1);
            }
            return -1;
        } finally {
            if (prepStmt != null) {
                prepStmt.close();
            }
        }
    }

    private static int getNextId(Connection connection) throws SQLException {
        int next = 0;
        Statement statement = null;
        try {
            statement = connection.createStatement();

            ResultSet rs = statement.executeQuery("select max(id) from ledger");
            while (rs.next()) {
                next = rs.getInt(1) + 1;
            }
            return next;
        } finally {
            if (statement != null)
                statement.close();
        }
    }

    @Override public String toString () {
        return "Ledger{" + "id=" + id + ", publicKey=" + publicKey + ", amount=" + amount + ", timestamp=" + timestamp +
                '}';
    }
}