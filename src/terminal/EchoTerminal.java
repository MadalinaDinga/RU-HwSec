package terminal;

import java.io.*;
import java.util.List;
import javax.swing.*;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.smartcardio.*;

public class EchoTerminal {
    static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };

    static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);

    public EchoTerminal() {
        super();
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
                                ResponseAPDU resp = applet.transmit(SELECT_APDU);

                                if (resp.getSW() != 0x9000) {
                                    System.err.println("Failed to select applet.");
                                    return;
                                }
                                // CLA, INS, P1, P2, data, response size
                                byte[] data = { 0x48, 0x65, 0x6c, 0x6c, 0x6f };
                                CommandAPDU capdu = new CommandAPDU((byte) 0xCC, (byte) 0x02, 0, 0, data, data.length);
                                System.out.println("Sent: " + capdu.toString());
                                System.out.println("Data: " + new String(capdu.getBytes()));
                                for(byte b : capdu.getBytes()) {
                                    System.out.print((int) (b & 0xFF) + " ");
                                }
                                System.out.println();
                                ResponseAPDU rapdu = applet.transmit(capdu);
                                System.out.println("Got response: " + rapdu.toString());
                                System.out.println("Got data: " + new String(rapdu.getBytes()));
                                for(byte b : rapdu.getBytes()) {
                                    System.out.print((int) (b & 0xFF) + " ");
                                }
                                System.out.println();
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