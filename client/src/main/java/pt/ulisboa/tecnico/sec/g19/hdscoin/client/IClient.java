package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public interface IClient {

    /**
     * Register the account and associated public key in the system before first use.
     * Initialize the proper structures to enable the use of the HDS coins.
     *
     * @param publicKey  Public key of the client.
     * @param privateKey Private key of the client, used to sign the message.
     * @param amount     Initial amount.
     * @throws RegisterException If there are any problems while trying to register a public key.
     */
    void register(ECPublicKey publicKey, ECPrivateKey privateKey, int amount) throws RegisterException;

    /**
     * Submit the request for transferring a given amount from account
     * source to account destination, if the balance of the source allows it.
     * The transfer will only be finalized when the receiver approves it via the receiveAmount() method.
     *
     * @param sourcePublicKey   Public key of the client that is sending the transaction.
     * @param targetPublicKey   Public key of the client that is receiving the transaction.
     * @param amount            Amount to transfer.
     * @param sourcePrivateKey  Private key of the client that is sending the transaction, used to sign the message.
     * @param previousSignature Signature of the last transaction.
     * @throws SendAmountException If there are any problems while trying to create a transaction.
     */
    void sendAmount(ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, int amount,
                    ECPrivateKey sourcePrivateKey, String previousSignature) throws SendAmountException;

    /**
     * Obtain the balance of the account associated with key.
     *
     * @param publicKey Public key of the client
     * @return CheckAccountResult containing the balance and pending transactions of the account
     */
    CheckAccountResult checkAccount(ECPublicKey publicKey) throws CheckAccountException;

    /**
     * Used by recipient of a transfer to accept in a non-repudiable way
     * a pending incoming transfer that was previously authorized by the
     * source.
     *
     * @param sourcePublicKey   Public key of the client (who receives money).
     * @param targetPublicKey   Public key of the ledger who sends money, in base 64 (as provided in the checkAccount response)
     * @param amount            The amount to receive (must match with the pending transaction)
     * @param sourcePrivateKey  Private key of the client, used to sign the message.
     * @param previousSignature Signature of the previous transaction of the client (who receives money)
     * @param incomingSignature Signature of the pending incoming transaction.
     * @throws ReceiveAmountException If there are any problems while trying to complete a transaction.
     */
    void receiveAmount(ECPublicKey sourcePublicKey, String targetPublicKey, int amount,
                       ECPrivateKey sourcePrivateKey, String previousSignature, String incomingSignature)
            throws ReceiveAmountException;

    /**
     * Obtain the full transaction history of the account associated with key.
     *
     * @param publicKey The public key of the account to be audited
     * @throws AuditException If there is a problem validating the transaction history.
     */
    List<Serialization.Transaction> audit(ECPublicKey publicKey) throws AuditException;

}