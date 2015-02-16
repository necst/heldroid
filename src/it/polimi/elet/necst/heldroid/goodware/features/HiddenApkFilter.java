package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.apk.DecodingException;
import it.polimi.elet.necst.heldroid.apk.PackageDecoder;
import it.polimi.elet.necst.heldroid.apk.PackageDecoders;
import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.io.File;
import java.io.FileReader;
import java.util.Collection;

public class HiddenApkFilter extends FeatureGatherer {
    private static final String FEATURE_NAME = "Hidden Apk";

    private static PackageDecoder decoder;

    private static char[][] SIGNATURES = {
        {0x50, 0x4B, 0x03, 0x04},
        {0x50, 0x4B, 0x05, 0x06},
        {0x50, 0x4B, 0x07, 0x08}
    };

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.FILE_ANALYSIS;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isFeatureEnabled(FEATURE_NAME))
            return false;

        Collection<File> allFiles = applicationData.getDecodedFileTree().getAllFiles();
        boolean apkPresent = false;

        for (File file : allFiles)
            if (isZipBased(file) && isApk(file)) {
                apkPresent = true;
                break;
            }

        super.setFeatureValue(0, apkPresent);

        return apkPresent;
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_NAME);
    }

    public static boolean isZipBased(File file) {
        try {
            FileReader reader = new FileReader(file);
            char[] signature = new char[SIGNATURES[0].length];
            reader.read(signature, 0, signature.length);
            reader.close();

            for (char[] VALID_SIGNATURE : SIGNATURES) {
                boolean match = true;

                for (int i = 0; i < VALID_SIGNATURE.length; i++)
                    if (signature[i] != VALID_SIGNATURE[i]) {
                        match = false;
                        break;
                    }

                if (match)
                    return true;
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isApk(File file) {
        if (decoder == null)
            decoder = PackageDecoders.apkTool();

        try {
            DecodedPackage dp = decoder.decode(file);
            dp.dispose();
            return true;
        } catch (DecodingException e) {
            return false;
        }
    }
}
