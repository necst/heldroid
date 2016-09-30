package it.polimi.elet.necst.heldroid.apk;

import java.io.File;

public class PackageDecoders {
    private static ApkToolDecoder apkToolDecoder;

    public static PackageDecoder apkTool() {
        if (apkToolDecoder != null)
            return apkToolDecoder;

        String currentDirectory = System.getProperty("user.dir");
        File tempDirectory = new File(currentDirectory, "apktool-tmp");

        if (!tempDirectory.exists())
            tempDirectory.mkdir();

        apkToolDecoder = new ApkToolDecoder(tempDirectory);

        return apkToolDecoder;
        //TODO: make sure to cleanup once done.
    }
}
