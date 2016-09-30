package it.polimi.elet.necst.heldroid;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        String[] newArgs = Arrays.copyOfRange(args, 1, args.length);
        String mode = args[0];

        try {
            if (mode.equals("filter"))
                it.polimi.elet.necst.heldroid.goodware.Main.main(newArgs);
            else if (mode.equals("detector"))
                it.polimi.elet.necst.heldroid.ransomware.Main.main(newArgs);
            else
                printUsage();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printUsage() {
        System.out.println("bin/heldroid (filter|detector) [options]");
        System.out.println("options depend on the command invoked");
    }
}
