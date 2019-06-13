package common;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import javacard.security.RSAPublicKey;


public class Logger {
    PrintWriter paymentLogPW;
    PrintWriter reloadLogPW;

    public Logger() throws IOException{
        paymentLogPW = new PrintWriter(new FileWriter("payment-log", true)); // true for append mode
        reloadLogPW = new PrintWriter(new FileWriter("reload-log", true)); 
    }

    public void writePayment(short amount, RSAPublicKey cardPublicKey, RSAPublicKey terminalPublicKey, byte[] proofOfPayment) {
        long timestamp = System.currentTimeMillis();
        paymentLogPW.println(timestamp+"; "+terminalPublicKey+"; "+cardPublicKey+"; "+amount+"; "+proofOfPayment+"\n");
        paymentLogPW.close();
    }

    public void writeReload(short amount, RSAPublicKey cardPublicKey, RSAPublicKey terminalPublicKey, byte[] proofOfPayment) {
        long timestamp = System.currentTimeMillis();
        reloadLogPW.println(timestamp+"; "+terminalPublicKey+"; "+cardPublicKey+"; "+amount+"; "+proofOfPayment+"\n");
        reloadLogPW.close();
    }

}