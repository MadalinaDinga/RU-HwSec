package common;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.interfaces.RSAPublicKey;


public class Logger {
    PrintWriter paymentLogPW;
    PrintWriter reloadLogPW;

    public Logger() throws IOException{
        paymentLogPW = new PrintWriter(new FileWriter("payment-log", true)); // true for append mode
        reloadLogPW = new PrintWriter(new FileWriter("reload-log", true)); 
    }

    /** Write payment transaction to payment log file */
    public void writePayment(int amount, RSAPublicKey cardPublicKey,
            RSAPublicKey terminalPublicKey, byte[] proofOfPayment,
            byte[] terminalNonce, byte[] cardNonce) throws IOException {
        long timestamp = System.currentTimeMillis();
        // Write to payment log file
        paymentLogPW.println("P; "+timestamp+"; "+terminalPublicKey+"; "+cardPublicKey+"; "+amount+"; "
        +proofOfPayment+"; "+terminalNonce+"; "+cardNonce+"\n");

        // Check error state
        if (paymentLogPW.checkError()) {
            throw new IOException();
        }
        paymentLogPW.close();
    }

    /** Write reload transaction to reload log file */
    public void writeReload(int amount, RSAPublicKey cardPublicKey,
        RSAPublicKey terminalPublicKey, byte[] proofOfPayment,
        byte[] terminalNonce, byte[] cardNonce) throws IOException {
        long timestamp = System.currentTimeMillis();
        // Write to reload log file
        reloadLogPW.println("R; "+timestamp+"; "+terminalPublicKey+"; "+cardPublicKey+"; "+amount+"; "
        +proofOfPayment+"; "+terminalNonce+"; "+cardNonce+"\n");

        // Check error state
        if (paymentLogPW.checkError()) {
            throw new IOException();
        }
        reloadLogPW.close();
    }

}