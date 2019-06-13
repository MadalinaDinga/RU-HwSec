/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

import static common.Constants.INS_ISSUE;
import static common.Constants.INS_PUBLIC_EXPONENT;
import static common.Constants.INS_PUBLIC_MODULUS;
import static common.Constants.INS_STORE_KEY_CERTIFICATE;
import static common.Constants.INS_STORE_MASTER_KEY;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author tom
 */
public class CLI {

    public static void main(String[] args) {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
    
    private RSAPublicKey masterPublicKey;
    private RSAPrivateKey masterPrivateKey;
    
    public boolean loadMasterKeys() {
        File f = new File("master-key-pub");
        if (f.exists() && !f.isDirectory()) {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                // Get private key from file
                byte[] data = readFile("master-key-priv");
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
                masterPrivateKey = (RSAPrivateKey) factory.generatePrivate(spec);
                // Get public key from file
                data = readFile("master-key-pub");
                X509EncodedKeySpec specPub = new X509EncodedKeySpec(data);
                masterPublicKey = (RSAPublicKey) factory.generatePublic(specPub);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
            return true;
        } else {
            return false;
        }
    }
    
    public void generateMasterKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            masterPublicKey = (RSAPublicKey) keypair.getPublic();
            masterPrivateKey = (RSAPrivateKey) keypair.getPrivate();

        
            /* Write public key to file. */
            writeKey(masterPublicKey, "master-key-pub");

            /* Write private key to file. */
            writeKey(masterPrivateKey, "master-key-priv");
        } catch (IOException ioe) {
            System.err.println("Failed to write generated master keys to disk.");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm not available.");
        }
    }
    
    public void generateTerminalKeyMaterial(String terminalType) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            RSAPublicKey terminalPublicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey terminalPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            Signature signer = Signature.getInstance("SHA1withRSA");

            signer.initSign(masterPrivateKey);
            signer.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getModulus()));
            signer.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getPublicExponent()));
            byte[] terminalCertificate = signer.sign();
            
            System.out.println("Start writing terminal keys to disk");
            
            try (
                FileOutputStream stream = new FileOutputStream(terminalType + "-certificate")
                ) {
                writeKey(terminalPublicKey, terminalType + "-key-pub");
                writeKey(terminalPrivateKey, terminalType + "-key-priv");
                stream.write(terminalCertificate);
            } catch (IOException e) {
                System.err.println("Failed to write certificate to disk.");
                e.printStackTrace();
            }
            
            
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to generate keys for terminal");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.err.println("Failed to generate certificate");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("Invalid signature key.");
            e.printStackTrace();
        }
    }
    
    public void generateReloadKeyMaterial() {
        generateTerminalKeyMaterial("reload");
    }
    
    public void generatePoSKeyMaterial() {
        generateTerminalKeyMaterial("pos");
    }
    
    /**
     * Issues a card by signing its key and providing the master verify key of
     * the PKI. It sets the cards state to ISSUED.
     * 
     * @return true if successfully initialized the card, false otherwise.
     */
    public boolean initializeCard() {
        CardChannel applet = null;
        try {
            applet = Utils.get();
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
        
        try {
            // Send master key modulus
            byte[] m = Utils.unsignedByteFromBigInt(masterPublicKey.getModulus());
            CommandAPDU capdu = new CommandAPDU((byte) 0x00, INS_STORE_MASTER_KEY, 0, 0, m, 0);
            ResponseAPDU rapdu = applet.transmit(capdu);
            
            // Send master key exponent
            byte[] e = Utils.unsignedByteFromBigInt(masterPublicKey.getPublicExponent());
            capdu = new CommandAPDU((byte) 0x00, INS_STORE_MASTER_KEY, 1, 0, e, 0);
            rapdu = applet.transmit(capdu);
            
            // Request modulus
            capdu = new CommandAPDU((byte) 0x00, INS_PUBLIC_MODULUS, 0, 0, null, 0);
            rapdu = applet.transmit(capdu);
            byte[] mod = rapdu.getData();
            
            // Request exponent
            capdu = new CommandAPDU((byte) 0x00, INS_PUBLIC_EXPONENT, 0, 0, null, 0);
            rapdu = applet.transmit(capdu);
            byte[] exp = rapdu.getData();

            // Create the signature on the key received by the card
            KeyFactory factory = KeyFactory.getInstance("RSA");
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(masterPrivateKey);
            signer.update(mod);
            signer.update(exp);
            byte[] signature = signer.sign();
            
            // Transmit the certificate to the card
            capdu = new CommandAPDU((byte) 0x00, INS_STORE_KEY_CERTIFICATE, 0, 0, signature, 0);
            rapdu = applet.transmit(capdu);

            // Issue the card.

            capdu = new CommandAPDU((byte) 0x00, INS_ISSUE, 0, 0, null, 0);
            rapdu = applet.transmit(capdu);
            

        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        } 
        return true;
    }

    /**
     * Reads the key from the file.
     * 
     * @return byte array with contents of the file.
     * 
     * @throws IOException if file could not be read.
     */
    public static byte[] readFile(String fname) throws IOException {
        FileInputStream in = new FileInputStream(fname);
        int length = in.available();
        byte[] data = new byte[length];
        in.read(data);
        in.close();
        return data;
    }

    /**
     * Writes <code>key</code> to file with name <code>filename</code> in standard
     * encoding (X.509 for RSA public key, PKCS#8 for RSA private key).
     *
     * @param key      the key to write.
     * @param filename the name of the file.
     *
     * @throws IOException if something goes wrong.
     */
    public static void writeKey(Key key, String filename) throws IOException {
        FileOutputStream file = new FileOutputStream(filename);
        file.write(key.getEncoded());
        file.close();
    }
    
}
