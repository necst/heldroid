package it.polimi.elet.necst.heldroid;

import java.io.File;
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
        String jarName =
            new File(Main.class.getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .getPath())
                .getName();

        System.out.println("Usage: ");
        System.out.println("java -jar " + jarName + ".jar (filter|detector) [options]");
        System.out.println("options depend on the mode of use of heldroid");
    }
}
