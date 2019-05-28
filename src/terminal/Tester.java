package terminal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher; 
import javax.smartcardio.CardChannel; 
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import common.Constants;

public class Tester {

    RSAPrivateKey masterPrivateKey;
    RSAPublicKey masterPublicKey;

    public void run() {
        try {
            CardChannel applet = Utils.get();

            loadKeys();

            testIssuing(applet);
            testAuthentication(applet);
        } catch (Exception e) {
            System.err.println("Failed to get cardchannel to the applet.");
        }
    }

    public void testAuthentication(CardChannel applet) {
        /*
         * Create required certificates for terminal
         */
        KeyPairGenerator generator = null;
        RSAPublicKey terminalPublicKey = null;
        RSAPrivateKey terminalPrivateKey = null;
        Signature signer = null;
        byte[] terminalCertificate = null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair keypair = generator.generateKeyPair();
            terminalPublicKey = (RSAPublicKey) keypair.getPublic();
            terminalPrivateKey = (RSAPrivateKey) keypair.getPrivate();

            signer = Signature.getInstance("SHA1withRSA");

            signer.initSign(masterPrivateKey);
            signer.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getModulus()));
            signer.update(Utils.unsignedByteFromBigInt(terminalPublicKey.getPublicExponent()));
            terminalCertificate = signer.sign();

            System.out.println(verifyCertificate(terminalCertificate, terminalPublicKey));

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to generate keys for terminal");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.err.println("Failed to generate certificate");
        } catch (InvalidKeyException e) {
            System.err.println("Invalid signature key.");
        }
        /*
         * Run the protocol
         */

        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[Constants.CHALLENGE_LENGTH];
        random.nextBytes(nonce);

        CommandAPDU startProtocol = new CommandAPDU(0xcc, Constants.START_AUTHENTICATION_PROTOCOL, 0, 0, null, 0);
        CommandAPDU modulus = new CommandAPDU(0xcc, 0, 0, 0,
                Utils.unsignedByteFromBigInt(terminalPublicKey.getModulus()), 0);
        CommandAPDU exponent = new CommandAPDU(0xcc, 0, 0, 0,
                Utils.unsignedByteFromBigInt(terminalPublicKey.getPublicExponent()), 0);
        CommandAPDU certificate = new CommandAPDU(0xcc, 0, 0, 0, terminalCertificate, 0);

        ResponseAPDU rapdu;

        
        try {
            // -1.
            System.out.println(startProtocol);
            rapdu = applet.transmit(startProtocol);
            System.out.println(rapdu.toString());
            // 0.
            System.out.println(modulus);
            rapdu = applet.transmit(modulus);
            System.out.println(rapdu.toString());
            BigInteger m = new BigInteger(1, rapdu.getData());
            // 1.
            System.out.println(exponent);
            rapdu = applet.transmit(exponent);
            System.out.println(rapdu.toString());
            BigInteger e = new BigInteger(1, rapdu.getData());
            RSAPublicKey pk = (RSAPublicKey) constructKey(m, e);
            // 2.
            System.out.println("Certificate Exchange"); 
            System.out.println(certificate);
            rapdu = applet.transmit(certificate);
            System.out.println(rapdu.toString());
            byte[] cert = rapdu.getData();
            if (!verifyCertificate(cert, pk)) {
                System.err.println("Certificate was not valid");
            }
            // 3.
            System.out.println("Challenge the card.");
            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            byte[] challenge = cipher.doFinal(nonce);
            CommandAPDU apdu = new CommandAPDU(0x00, 0, 0, 0, challenge, 0);
            System.out.println(apdu +"\n" + challenge.length);
            rapdu = applet.transmit(apdu);
            System.out.println(rapdu.toString());
            byte[] response = rapdu.getData();
            if (! Arrays.equals(nonce, response)) {
                System.err.println("Challenge failed");
                System.err.println("Challenge: " + new BigInteger(1, nonce));
                System.err.println("Response: " + new BigInteger(1, response));
            } else {
                System.out.println("Card has correctly responded to challenge");
            }
            // 4.
            System.out.println("Get challenge from card.");
            CommandAPDU getChallenge = new CommandAPDU(0x00, 0, 0, 0, null, 0);
            System.out.println(getChallenge);
            rapdu = applet.transmit(getChallenge);
            System.out.println(rapdu.toString());
            cipher.init(Cipher.DECRYPT_MODE, terminalPrivateKey);
            byte[] ans = cipher.doFinal(rapdu.getData());
            System.out.println("Response length: "  + ans.length);
            // 5.
            System.out.println("Respond to challenge from card");
            CommandAPDU challengeResponse = new CommandAPDU(0x00, 0, 0, 0, ans, 0);
            rapdu = applet.transmit(challengeResponse);
            System.out.println(rapdu.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void testIssuing(CardChannel applet) {

    }

    public boolean verifyCertificate(byte[] certificate, RSAPublicKey key) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(masterPublicKey);
        verifier.update(Utils.unsignedByteFromBigInt(key.getModulus()));
        verifier.update(Utils.unsignedByteFromBigInt(key.getPublicExponent()));
        return verifier.verify(certificate);
    }

    public PublicKey constructKey(BigInteger modulus, BigInteger exponent) throws NoSuchAlgorithmException, InvalidKeySpecException{
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(spec);
        return pk;
    }

    public void loadKeys() {
        try {
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
        } catch (IOException ioe) {
            System.err.println("Failed to load keys.");
            ioe.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm not available");
        } catch (InvalidKeySpecException e) {
            System.err.println("Keyspec is invalid");
        }
    }

    public static void main(String[] args) {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        (new Tester()).run();
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