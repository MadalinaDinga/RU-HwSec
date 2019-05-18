package terminal;

import java.io.*;
import java.util.List;
import javax.swing.*;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EchoTerminal {

    private static final byte INS_GIVE_KEY_EXP = (byte) 0x03;
    private static final byte INS_GIVE_KEY_MOD = (byte) 0x04;

    private static final byte INS_GIVE_KEY_PUB_EXP = (byte) 0x05;
    private static final byte INS_SIGN = (byte) 0x06;

    static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };

    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            APPLET_AID);

    public EchoTerminal() {
        super();
        System.out.println("ECHO");
    }

    public static void main(String[] args) {
        new EchoTerminal().run();
    }

    public void sign(CardChannel applet, byte[] data) throws Exception {
        data = new byte[]{0x01, 0x02, 0x04, 0x05, 0x06, 0x07};
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        // Request modulus
        CommandAPDU capdu = new CommandAPDU((byte) 0xCC, (byte) 0x04, 0, 0, null, 200);
        ResponseAPDU rapdu = applet.transmit(capdu);
        BigInteger modulus = new BigInteger(1, rapdu.getData() );
        System.out.println("Modulus bytes: " + rapdu.getData().length );
        System.out.println("Modulus: " + modulus );
        // Request exponent
        capdu = new CommandAPDU((byte) 0xCC, (byte) 0x05, 0, 0, null, 200);
        rapdu = applet.transmit(capdu);
        BigInteger exponent = new BigInteger(1, rapdu.getData() );
        System.out.println("Exponent bytes: " + rapdu.getData().length );
        System.out.println("Exponent: " + exponent );

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey pub = factory.generatePublic(spec);
        Signature verifier = Signature.getInstance("SHA1withRSA");
        verifier.initVerify(pub);

        capdu = new CommandAPDU((byte) 0xCC, INS_SIGN, 0, 0, data, data.length);
        rapdu = applet.transmit(capdu);
    

        byte[] sig = rapdu.getData();

        System.out.println("Signature has bytes: " + sig.length);

        verifier.update(data); // Or whatever interface specifies.
        boolean okay = verifier.verify(sig);

        if (okay) {
            System.out.println("Verified!");
        } else {
            System.err.println("Failed");
        }


    }

    public void run() {
        try {
            TerminalFactory tf = TerminalFactory.getDefault();
            CardTerminals ct = tf.terminals();
            List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);

            if (cs.isEmpty()) {
                System.err.println("No terminals with card found.");
                return;
            }

            try {
                for (CardTerminal cardReader : cs) {
                    if (cardReader.isCardPresent()) {
                        try {
                            // connect using any protocol
                            Card card = cardReader.connect("*");

                            System.out.println("Connected!");

                            try {
                                CardChannel applet = card.getBasicChannel();
                                ResponseAPDU resp = applet.transmit(SELECT_APDU);

                                if (resp.getSW() != 0x9000) {
                                    System.err.println("Failed to select applet.");
                                    return;
                                }

                                byte[] data = { 0x48, 0x65, 0x6c, 0x6c, 0x6f };
                                // CLA, INS, P1, P2, data, response size
                                CommandAPDU capdu = new CommandAPDU((byte) 0xCC, (byte) 0x02, 0, 0, data, data.length);
                                System.out.println("Sent: " + capdu.toString());
                                System.out.println("Data: " + new String(capdu.getBytes()));
                                for (byte b : capdu.getBytes()) {
                                    System.out.print((int) (b & 0xFF) + " ");
                                }
                                System.out.println();

                                ResponseAPDU rapdu = applet.transmit(capdu);
                                System.out.println("Got response: " + rapdu.toString());
                                System.out.println("Got data: " + new String(rapdu.getBytes()));
                                for (byte b : rapdu.getBytes()) {
                                    System.out.print((int) (b & 0xFF) + " ");
                                }
                                System.out.println();

                                // go(applet);
                                byte[] d = {'H', 'E', 'L', 'L', 'O'};
                                sign(applet, d);

                            } catch (SecurityException e) {
                                System.err.println("Caller does not have required permission");
                            } catch (IllegalStateException e) {
                                System.err.println("this card object has been disposed of via the disconnect() method");
                            }
                        } catch (CardNotPresentException e) {
                            System.err.println("No card present.");
                        } catch (CardException e) {
                            System.err.println(
                                    "Connection could not be established using the specified protocol or if a connection has previously been established using a different protocol");
                        }
                    }
                }
            } catch (CardException e) {
                System.err.println("The status could not be determined");
            }
        } catch (CardException e) {
            System.err.println("The card operation failed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void go(CardChannel applet) throws CardException {
        CommandAPDU capdu = new CommandAPDU((byte) 0xCC, (byte) 0x03, 0, 0, null, 200);
        System.out.println("Sent: " + capdu.toString());
        System.out.println("Data: " + new String(capdu.getBytes()));
        for (byte b : capdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }
        System.out.println();

        ResponseAPDU rapdu = applet.transmit(capdu);
        System.out.println("Got response: " + rapdu.toString());
        System.out.println("PrivExp");
        System.out.println("Got data: " + new String(rapdu.getBytes()));
        for (byte b : rapdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }
        BigInteger exp = new BigInteger(1, Arrays.copyOfRange(rapdu.getBytes(), 0, rapdu.getBytes().length - 2) );
        System.out.println("\nPrivExp:: " + exp);
        
        System.out.println("\n\n\n");

        capdu = new CommandAPDU((byte) 0xCC, (byte) 0x04, 0, 0, null, 200);
        System.out.println("Sent: " + capdu.toString());
        System.out.println("Data: " + new String(capdu.getBytes()));
        for (byte b : capdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }
        System.out.println();

        rapdu = applet.transmit(capdu);
        System.out.println("Got response: " + rapdu.toString());
        System.out.println("Modulus");
        System.out.println("Got data: " + new String(rapdu.getBytes()));
        for (byte b : rapdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }

        BigInteger modulus = new BigInteger(1, Arrays.copyOfRange(rapdu.getBytes(), 0, rapdu.getBytes().length - 2) );
        System.out.println("Modulus:: " + modulus);
        System.out.println("\n\n\n");

        capdu = new CommandAPDU((byte) 0xCC, (byte) 0x05, 0, 0, null, 200);
        System.out.println("Sent: " + capdu.toString());
        System.out.println("Data: " + new String(capdu.getBytes()));
        for (byte b : capdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }
        System.out.println();

        rapdu = applet.transmit(capdu);
        System.out.println("Got response: " + rapdu.toString());
        System.out.println("PubExp");
        System.out.println("Got data: " + new String(rapdu.getBytes()));
        for (byte b : rapdu.getBytes()) {
            System.out.print((int) (b & 0xFF) + " ");
        }
        System.out.println("\n\n\n");
    }
}