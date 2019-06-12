/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author tom
 */
public abstract class Protocol {
    
    public abstract boolean run(CardChannel applet);
    
    protected ResponseAPDU sendCommand(CardChannel applet, CommandAPDU capdu, int expectedSW, String reason) throws CardException {
        ResponseAPDU rapdu = applet.transmit(capdu);
        if (rapdu.getSW() != expectedSW) 
                throw new CardException(reason + rapdu.getSW());
        System.out.println(rapdu);
        return rapdu;
    }
    
    protected CommandAPDU empty() {
        return new CommandAPDU(0, 0, 0, 0, null, 0);
    }
    
    protected boolean verifyChallengeResponse(byte[] tag, byte[] challenge, byte[] signature, RSAPublicKey verifyKey) {
        return verifyKeyCertificate(tag, challenge, signature, verifyKey);
    }
    
    protected boolean verifyKeyCertificate(byte[] modulus, byte[] exponent, byte[] certificate, RSAPublicKey verificationKey) {
        try{
            Signature verifier = Signature.getInstance("SHA1withRSA");
        
            verifier.initVerify(verificationKey);
            verifier.update(modulus);
            verifier.update(exponent);
            
            return verifier.verify(certificate);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    protected RSAPublicKey buildCardKeys(byte[] modulus, byte[] exponent) throws CardException {
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pk = kf.generatePublic(spec);
            return (RSAPublicKey) pk;
        } catch (Exception e) {
            e.printStackTrace();
            throw new CardException("Key received from the card is not valid");
        }
    }
}
