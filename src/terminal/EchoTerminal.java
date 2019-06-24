package terminal;

import java.util.List;
import javax.smartcardio.*;

public class EchoTerminal {
    static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };

    public EchoTerminal() {
        System.out.println("ECHO");
    }

    public static void main(String[] args) {
        new EchoTerminal().run();
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
                            } catch (SecurityException e) {
                                System.err.println("Caller does not have required permission");
                            } catch (IllegalStateException e) {
                                System.err.println("this card object has been disposed of via the disconnect() method");
                            }
                        } catch (CardNotPresentException e) {
                            System.err.println("No card present.");
                        } catch (CardException e) {
                            System.err.println("Connection could not be established using the specified protocol or if a connection has previously been established using a different protocol");
                        }
                    }
                }
            } catch (CardException e) {
                System.err.println("The status could not be determined");
            }
        } catch (CardException e) {
            System.err.println("The card operation failed");
        }
    }
}