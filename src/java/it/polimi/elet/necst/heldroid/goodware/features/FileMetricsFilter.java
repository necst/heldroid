package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.pipeline.FileTree;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.io.File;

public class FileMetricsFilter extends FeatureGatherer {
    private ApplicationData currentData;

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        this.currentData = applicationData;

        this.detectLanguageEncoding();
        this.checkFileMetrics();
        this.checkApplicationMetrics();

        return false;
    }

    private void detectLanguageEncoding() {
        if (!super.isFeatureEnabled(FEATURE_LANGUAGE))
            return;

        String apkName = currentData.getDecodedPackage().getOriginalApk().getName();
        Character.UnicodeBlock detectedApkNameBlock = detectUnicodeBlock(apkName);

        if (!detectedApkNameBlock.equals(Character.UnicodeBlock.BASIC_LATIN)) {
            super.setFeatureValue(0, detectedApkNameBlock.toString());
        }

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();
        final Wrapper<String> language = new Wrapper<String>("BASIC_LATIN");

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                Character.UnicodeBlock block = detectUnicodeBlock(value);

                if (!block.equals(Character.UnicodeBlock.BASIC_LATIN)) {
                    language.value = block.toString();
                    return true;
                }

                return false;
            }
        });

        constantFinder.searchAllLiterals();
        super.setFeatureValue(0, language.value);
    }

    private Character.UnicodeBlock detectUnicodeBlock(String string) {
        for (int i = 0; i < string.length(); i++) {
            Character.UnicodeBlock block = Character.UnicodeBlock.of(string.charAt(i));

            for (Character.UnicodeBlock interestingBlock : INTERESTING_UNICODE_BLOCKS) {
                if (block.equals(interestingBlock))
                    return block;
            }
        }

        return Character.UnicodeBlock.BASIC_LATIN;
    }

    private void checkFileMetrics() {
        File apk = currentData.getDecodedPackage().getOriginalApk();

        super.setFeatureValue(1, apk.length());

        if (!super.isAnyFeatureEnabled(FEATURE_FILES_COUNT, FEATURE_IMAGES_COUNT))
            return;

        FileTree tree = currentData.getDecodedFileTree();
        int totalFiles = 0;
        int totalImages = 0;

        for (File file : tree.getAllFiles()) {
            String name = file.getName();

            for (String imageExtension : IMAGE_EXTENSIONS)
                if (name.endsWith(imageExtension)) {
                    totalImages++;
                    break;
                }

            totalFiles++;
        }

        super.setFeatureValue(2, totalImages);
        super.setFeatureValue(3, totalFiles);
    }

    private void checkApplicationMetrics() {
        super.setFeatureValue(4, currentData.getManifestReport().getPermissions().size());

        if (!super.isAnyFeatureEnabled(FEATURE_RECEIVERS_COUNT, FEATURE_SERVICES_COUNT, FEATURE_ACTIVITIES_COUNT))
            return;

        SmaliLoader loader = currentData.getSmaliLoader();
        int totalActivities = 0;
        int totalServices = 0;
        int totalReceivers = 0;

        for (SmaliClass klass : loader.getClasses()) {
            if (klass.isSubclassOf(ACTIVITY))
                totalActivities++;
            else if (klass.isSubclassOf(SERVICE))
                totalServices++;
            else if (klass.isSubclassOf(BROADCAST_RECEIVER))
                totalReceivers++;
        }

        super.setFeatureValue(5, totalActivities);
        super.setFeatureValue(6, totalServices);
        super.setFeatureValue(7, totalReceivers);
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_LANGUAGE);

        super.addFeature(FEATURE_TOTAL_SIZE);
        super.addFeature(FEATURE_IMAGES_COUNT);
        super.addFeature(FEATURE_FILES_COUNT);

        super.addFeature(FEATURE_PERMISSIONS_COUNT);
        super.addFeature(FEATURE_ACTIVITIES_COUNT);
        super.addFeature(FEATURE_SERVICES_COUNT);
        super.addFeature(FEATURE_RECEIVERS_COUNT);
    }

    private static final String FEATURE_LANGUAGE = "Language:";
    private static final String FEATURE_TOTAL_SIZE = "Size of apk";
    private static final String FEATURE_IMAGES_COUNT = "Number of images";
    private static final String FEATURE_FILES_COUNT = "Number of files";
    private static final String FEATURE_PERMISSIONS_COUNT = "Number of permissions";
    private static final String FEATURE_ACTIVITIES_COUNT = "Number of activities";
    private static final String FEATURE_SERVICES_COUNT = "Number of services";
    private static final String FEATURE_RECEIVERS_COUNT = "Number of receivers";

    private static final String[] IMAGE_EXTENSIONS = { ".jpg", ".jpeg", ".bmp", ".png", ".gif", ".tga", ".dds", ".blp" };

    private static final SmaliClassName BROADCAST_RECEIVER = new SmaliClassName("Landroid/content/BroadcastReceiver;");
    private static final SmaliClassName ACTIVITY = new SmaliClassName("Landroid/app/Activity;");
    private static final SmaliClassName SERVICE = new SmaliClassName("Landroid/app/Service;");

    private static final Character.UnicodeBlock[] INTERESTING_UNICODE_BLOCKS = {
            Character.UnicodeBlock.ARABIC,
            Character.UnicodeBlock.ARMENIAN,
            Character.UnicodeBlock.BENGALI,
            Character.UnicodeBlock.CHEROKEE,
            Character.UnicodeBlock.CYRILLIC,
            Character.UnicodeBlock.DEVANAGARI,
            Character.UnicodeBlock.ETHIOPIC,
            Character.UnicodeBlock.GEORGIAN,
            Character.UnicodeBlock.GOTHIC,
            Character.UnicodeBlock.GREEK,
            Character.UnicodeBlock.GUJARATI,
            Character.UnicodeBlock.GURMUKHI,
            Character.UnicodeBlock.HANUNOO,
            Character.UnicodeBlock.HEBREW,
            Character.UnicodeBlock.HIRAGANA,
            Character.UnicodeBlock.KANBUN,
            Character.UnicodeBlock.KANNADA,
            Character.UnicodeBlock.KATAKANA,
            Character.UnicodeBlock.KHMER,
            Character.UnicodeBlock.LAO,
            Character.UnicodeBlock.LIMBU,
            Character.UnicodeBlock.MALAYALAM,
            Character.UnicodeBlock.MONGOLIAN,
            Character.UnicodeBlock.MONGOLIAN,
            Character.UnicodeBlock.OGHAM,
            Character.UnicodeBlock.ORIYA,
            Character.UnicodeBlock.OSMANYA,
            Character.UnicodeBlock.SHAVIAN,
            Character.UnicodeBlock.SINHALA,
            Character.UnicodeBlock.SYRIAC,
            Character.UnicodeBlock.TAGBANWA,
            Character.UnicodeBlock.TAI_LE,
            Character.UnicodeBlock.TAI_XUAN_JING_SYMBOLS,
            Character.UnicodeBlock.TAMIL,
            Character.UnicodeBlock.THAANA,
            Character.UnicodeBlock.THAI,
            Character.UnicodeBlock.TIBETAN,
            Character.UnicodeBlock.UGARITIC
    };
}
