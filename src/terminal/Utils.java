package terminal;

import java.math.BigInteger;
import java.util.List;

import javax.smartcardio.*;

import common.Constants;

public class Utils {

    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,
            Constants.APPLET_AID);

    /**
     * Gets an unsigned byte array representation of <code>big</code>. A leading
     * zero (present only to hold sign bit) is stripped.
     * 
     * @param big a big integer.
     * 
     * @return a byte array containing a representation of <code>big</code>.
     */
    public static byte[] unsignedByteFromBigInt(BigInteger big) {
        byte[] data = big.toByteArray();
        if (data[0] == 0) {
            byte[] tmp = data;
            data = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
        }
        return data;
    }

    public static CardChannel get() throws Exception {
        try {
            TerminalFactory tf = TerminalFactory.getDefault();
            CardTerminals ct = tf.terminals();
            List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);

            if (cs.isEmpty()) {
                System.err.println("No terminals with card found.");
                throw new Exception();
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

                                return applet;

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
        throw new Exception();
    }

}