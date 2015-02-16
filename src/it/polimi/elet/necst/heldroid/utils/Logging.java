package it.polimi.elet.necst.heldroid.utils;

import java.io.OutputStream;
import java.io.PrintStream;

public class Logging {
    private static PrintStream originalOut, originalErr;

    public static void suppressOut() {
        originalOut = System.out;

        PrintStream dummyStream = new PrintStream(new OutputStream(){
            public void write(int b) { }
        });

        System.setOut(dummyStream);
    }

    public static void restoreOut() {
        System.setOut(originalOut);
        originalOut = null;
    }

    public static void suppressErr() {
        originalErr = System.err;

        PrintStream dummyStream = new PrintStream(new OutputStream(){
            public void write(int b) { }
        });

        System.setErr(dummyStream);
    }

    public static void restoreErr() {
        System.setErr(originalErr);
        originalErr = null;
    }

    public static void suppressAll() {
        suppressOut();
        suppressErr();
    }

    public static void restoreAll() {
        restoreErr();
        restoreOut();
    }
}
