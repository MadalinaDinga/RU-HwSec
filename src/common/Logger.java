package common;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class Logger {
    PrintWriter paymentLogPW;
    PrintWriter reloadLogPW;

    public Logger() throws IOException{
        paymentLogPW = new PrintWriter(new FileWriter("payment-log", true)); // true for append mode
        reloadLogPW = new PrintWriter(new FileWriter("reload-log", true)); 
    }

    public void writePayment(short amount, byte[] cId, byte[] tId) {
        long timestamp = System.currentTimeMillis();
        paymentLogPW.println(timestamp+" "+tId+""+cId+" "+amount);
        paymentLogPW.close();
    }

    public void writeReload(short amount, byte[] cId, byte[] tId) {
        long timestamp = System.currentTimeMillis();
        reloadLogPW.println(timestamp+" "+tId+""+cId+" "+amount);
        reloadLogPW.close();
    }

}