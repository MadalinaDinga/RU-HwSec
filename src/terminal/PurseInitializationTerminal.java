package terminal;

import static common.Constants.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;

import javax.smartcardio.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import common.Constants;

public class PurseInitializationTerminal {

    static RSAPrivateKey masterPrivateKey;
    static RSAPublicKey masterPublicKey;

    public static void main(String[] args) throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);


        File f = new File("master-key-pub");
        if (f.exists() && !f.isDirectory()) {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            // Get private key from file
            byte[] data = readFile("master-key-priv");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
            masterPrivateKey = (RSAPrivateKey) factory.generatePrivate(spec);
            System.out.println("Loaded private key.");
            // Get public key from file
            data = readFile("master-key-pub");
            X509EncodedKeySpec specPub = new X509EncodedKeySpec(data);
            masterPublicKey = (RSAPublicKey) factory.generatePublic(specPub);
            System.out.println("Loaded public key.");
        } else {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            masterPublicKey = (RSAPublicKey) keypair.getPublic();
            masterPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            /* Write public key to file. */
            writeKey(masterPublicKey, "master-key-pub");

            /* Write private key to file. */
            writeKey(masterPrivateKey, "master-key-priv");
        }

        issueCardCertificate(Utils.get());

        verifyCardCertificate(Utils.get());

    }

    private static void verifyCardCertificate(CardChannel applet) throws CardException {

        CommandAPDU capdu = new CommandAPDU((byte) 0xcc, Constants.INS_PUBLIC_MODULUS, 0, 0, null, 0);
        ResponseAPDU rapdu = applet.transmit(capdu);
        BigInteger modulus = new BigInteger(1, rapdu.getData() );

        capdu = new CommandAPDU((byte) 0xcc, Constants.INS_PUBLIC_EXPONENT, 0, 0, null, 0);
        rapdu = applet.transmit(capdu);
        BigInteger exponent = new BigInteger(1, rapdu.getData() );

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);

        try {

            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pub = factory.generatePublic(spec);

            // capdu = new CommandAPDU((byte) 0xCC, Constants.INS_KEY_CERTIFICATE, 0, 0, null, 0);
            capdu = new CommandAPDU((byte) 0x01, Constants.INS_KEY_CERTIFICATE, 0, 0, null, 0);
            rapdu = applet.transmit(capdu);
            byte[] certificate = rapdu.getData();

            Signature verifier = Signature.getInstance("SHA1withRSA");
            verifier.initVerify(masterPublicKey);
            verifier.update(Utils.unsignedByteFromBigInt(modulus));
            verifier.update(Utils.unsignedByteFromBigInt(exponent));
            if (verifier.verify(certificate)) {
                System.out.println("Certificate is valid.");
            } else {
                System.err.println("Invalid certificate, signatures does not verify");
            }


        } catch (InvalidKeySpecException e) {
            System.err.println("Invalid key spec as result of data from card");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Keyfactory for specified algorithm not available");
        } catch (InvalidKeyException e) {
            System.err.println("Invalid key given to signature object.");
        } catch (SignatureException e) {
            System.err.println("Signature object was not properly initialized.");
        }

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

    /**
     * Pops up dialog to ask user to select file and reads the file.
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

    public static void issueCardCertificate(CardChannel applet) throws CardException {
        System.out.println("Transfering master key over.");
        // Send master key
        byte[] m = Utils.unsignedByteFromBigInt(masterPublicKey.getModulus());
        CommandAPDU capdu = new CommandAPDU((byte) 0xCC, INS_STORE_MASTER_KEY, 0, 0, m, 0);
        ResponseAPDU rapdu = applet.transmit(capdu);
        System.out.println(rapdu.toString());
        byte[] e = Utils.unsignedByteFromBigInt(masterPublicKey.getPublicExponent());
        capdu = new CommandAPDU((byte) 0xCC, INS_STORE_MASTER_KEY, 1, 0, e, 0);
        rapdu = applet.transmit(capdu);
        System.out.println(rapdu.toString());
        
        System.out.println("Requesting Modulus.");
        // Request modulus
        capdu = new CommandAPDU((byte) 0xCC, INS_PUBLIC_MODULUS, 0, 0, null, 200);
        rapdu = applet.transmit(capdu);
        byte[] mod = rapdu.getData();
        BigInteger modulus = new BigInteger(1, mod);
        System.out.println("Modulus bytes: " + mod.length);
        System.out.println("Modulus: " + modulus);

        System.out.println("Requesting Exponent");
        // Request exponent
        capdu = new CommandAPDU((byte) 0xCC, INS_PUBLIC_EXPONENT, 0, 0, null, 200);
        rapdu = applet.transmit(capdu);
        byte[] exp = rapdu.getData();
        BigInteger exponent = new BigInteger(1, exp);
        System.out.println("Exponent bytes: " + exp.length);
        System.out.println("Exponent: " + exponent);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);

        try {
            System.out.println("Signing key");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pub = factory.generatePublic(spec);
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(masterPrivateKey);
            signer.update(mod);
            signer.update(exp);
            byte[] signature = signer.sign();
            System.out.println("Signed Key. Transmitting certificate (" + signature.length + " bytes).");
            capdu = new CommandAPDU((byte) 0xCC, INS_STORE_KEY_CERTIFICATE, 0, 0, signature, 0);
            rapdu = applet.transmit(capdu);
            System.out.println(rapdu.toString());

            System.out.println("Issuing card.");

            capdu = new CommandAPDU((byte) 0xCC, INS_ISSUE, 0, 0, null, 0);
            rapdu = applet.transmit(capdu);
            System.out.println("Verifying signature on card. ");
            capdu = new CommandAPDU((byte) 0xCC, INS_VERIFY, 0, 0, signature, 0);
            rapdu = applet.transmit(capdu);
            System.out.println(rapdu.toString());

        } catch (InvalidKeySpecException ex) {
            System.err.println("Failed to construct key from given modulus and exponent");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Algorithm is not available");
        } catch (InvalidKeyException ex) {
            System.err.println("Invalid key provided to Signature obj.");
        } catch (SignatureException ex) {
            System.err.println("Failed to call update on Signature obj");
        }   

        
        

    }

}