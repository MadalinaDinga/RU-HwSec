/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

import common.Constants;
import java.nio.ByteBuffer;
import java.security.Signature;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author madalina
 */
public class ReloadProtocol extends Protocol {
    
    private final ReloadGUI gui;
    private final RSAPrivateKey terminalPrivateKey;
    private final RSAPublicKey terminalPublicKey;
    private final RSAPublicKey cardVerifyKey;
    private final int amount;
    public byte[] proofOfReload;
    
    public ReloadProtocol(ReloadGUI gui,
            int amount,
            RSAPublicKey terminalPubKey,
            RSAPrivateKey terminalPrivateKey,
            RSAPublicKey cardVerifyKey) {
        this.gui = gui;
        this.amount = amount;
        this.terminalPublicKey = terminalPubKey;
        this.terminalPrivateKey = terminalPrivateKey;
        this.cardVerifyKey = cardVerifyKey;
    }
    
    /**
     * Runs the Reload protocol and sets the field proofOfReload upon success.
     * @return True if successfully loaded the amount, false otherwise.
     */
    public boolean run(CardChannel applet) {
        ResponseAPDU rapdu;
        
        try {
            // Signal start of the protocol
            rapdu = sendCommand(applet, startReload(), 0x9000, "Start authentication message returned SW: ");
        
            // Send the amount
            ByteBuffer buff = ByteBuffer.allocate(2);
            buff.putShort((short) amount);
            byte[] amountBytes = buff.array();
                        
            try {
                rapdu = sendCommand(applet, amount(amountBytes), 0x9000, "Sending over the amount resulted in SW: ");
            } catch (CardException e) {
                throw e;
            }
            // transaction counter
            byte[] cardNonce = rapdu.getData();
        
            // Send nonce to the card
            byte[] nonce = new byte[Constants.CHALLENGE_LENGTH];  
            
            //TODO: add tag
            rapdu = sendCommand(applet, nonce(nonce), 0x9000, "Sending over the nonce resulted in SW: ");
            byte[] signature = rapdu.getData();
            
            // Verify that both the card and terminal have observed the same values
            if (!verifyCardSignature(amountBytes, nonce, cardNonce, signature)) {
                System.err.println("Signature not valid.");
                return false;
            }
            
            byte[] signedValues = signValues(amountBytes, nonce, cardNonce);
            rapdu = sendCommand(applet, signature(signedValues), 0x9000, "Sending over signature of values resulted in SW: ");
            byte[] proofOfReload = rapdu.getData();
            
            // Verify performed reload.
            if (!verifyReload(amountBytes, nonce, cardNonce, proofOfReload)) {
                System.err.println("Transaction invalid");
                return false;
            }
            
            this.proofOfReload = proofOfReload;
            
            System.out.println("Valid transaction.");
            
        } catch (CardException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    private CommandAPDU startReload() {
        return new CommandAPDU(0, Constants.START_RELOAD_PROTOCOL, 0, 0, null, 0);
    }
    
    private CommandAPDU amount(byte[] amount) {
        return new CommandAPDU(0, 0, 0, 0, amount, 0);
    }
    
    private CommandAPDU nonce(byte[] nonce) {
        return new CommandAPDU(0, 0, 0, 0, nonce, 0);
    }
    
    private CommandAPDU signature(byte[] signature) {
        return new CommandAPDU(0, 0, 0, 0, signature, 0);
    }
    
    private boolean verifyReload(byte[] amount, byte[] tNonce, byte[] cNonce, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(cardVerifyKey);
            
            sig.update(amount);
            sig.update(tNonce);
            sig.update(cNonce);
            sig.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getModulus()) );
            sig.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getPublicExponent()) );
               
            return sig.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private boolean verifyCardSignature(byte[] amount, byte[] nonce, byte[] counter, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(cardVerifyKey);

            sig.update(amount);
            sig.update(nonce);
            sig.update(counter);

            if (sig.verify(signature)) {
                System.out.println("Signature is valid");
                return true;
            } else {
                System.err.println("Signature on nonces and amount is invalid");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private byte[] signValues(byte[] amount, byte[] nonce, byte[] counter) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(terminalPrivateKey);

            sig.update(amount);
            sig.update(nonce);
            sig.update(counter);

            return sig.sign(); 
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
}
