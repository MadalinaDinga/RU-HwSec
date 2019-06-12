/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

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
        return rapdu;
    }
}
