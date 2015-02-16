package it.polimi.elet.necst.heldroid.apk;

import java.io.*;

class ApkToolDecoder implements PackageDecoder {
    private static final File APK_TOOL_JAR = new File("apktool.jar");

    private static final String APK_EXTENSION = ".apk";

    private File outputDirectory;

    public ApkToolDecoder(File outputDirectory) {
        this.outputDirectory = outputDirectory;
    }

    @Override
    public DecodedPackage decode(File apkFile) throws DecodingException {
        if (!apkFile.getName().toLowerCase().endsWith(APK_EXTENSION))
            throw new DecodingException("Invalid file type.");

        String apkName = apkFile.getName();
        File workingDirectory = new File(outputDirectory, apkName);

        try {
            if (workingDirectory.exists())
                return new ApkToolOutput(apkFile, workingDirectory);

            /* Windows
            Process p =
                Runtime.getRuntime().exec(
                    String.format("java -jar %s decode -f -o \"%s\" \"%s\"",
                        APK_TOOL_JAR.getAbsolutePath(),
                        workingDirectory.getAbsolutePath(),
                        apkFile.getAbsolutePath())); */

            Process p =
                Runtime.getRuntime().exec(new String[] {
                    "java", "-jar", APK_TOOL_JAR.getAbsolutePath(),
                    "decode", "-o", workingDirectory.getAbsolutePath(),
                    apkFile.getAbsolutePath()
                });

            exhaustStreamAsync(p.getInputStream());
            exhaustStreamAsync(p.getErrorStream());

            p.waitFor();

            DecodedPackage result = new ApkToolOutput(apkFile, workingDirectory);

            if (result.getAndroidManifest().exists() && result.getSmaliDirectory().exists())
                return result;

            throw new DecodingException("No manifest or smali directory produced!");
        } catch (Exception e) {
            throw new DecodingException(e);
        }
    }

    private static void exhaustStream(InputStream inputStream) {
        InputStreamReader reader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(reader);

        try {
            while (bufferedReader.readLine() != null)
                ;
            inputStream.close();
        } catch (IOException e) { }
    }

    private static void exhaustStreamAsync(final InputStream inputStream) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                exhaustStream(inputStream);
            }
        }).start();
    }
}
