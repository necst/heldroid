package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

public class SuspiciousIntentFilter extends FeatureGatherer {
    @Override
    public OperationMode getOperationMode() {
        return OperationMode.FILE_ANALYSIS;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isAnyFeatureEnabled(FEATURE_PREFIX))
            return false;

        final boolean[] intentFound = new boolean[SUSPICIOUS_INTENTS.length];
        final Wrapper<Boolean> somethingFound = new Wrapper<Boolean>();

        somethingFound.value = false;

        for (String intent : applicationData.getManifestReport().getIntentFilters())
            for (int i = 0; i < SUSPICIOUS_INTENTS.length; i++)
                if (intent.endsWith(SUSPICIOUS_INTENTS[i])) {
                    intentFound[i] = true;
                    somethingFound.value = true;
                }

        if (somethingFound.value == false) {
            SmaliLoader loader = applicationData.getSmaliLoader();
            SmaliConstantFinder constantFinder = loader.generateConstantFinder();

            constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
                @Override
                public boolean constantFound(String intentName) {
                    for (int i = 0; i < SUSPICIOUS_INTENTS.length; i++)
                        if (intentName.endsWith(SUSPICIOUS_INTENTS[i])) {
                            intentFound[i] = true;
                            somethingFound.value = true;
                        }
                    return false;
                }
            });

            constantFinder.searchParameters(ADD_ACTION, 0);
        }

        for (int i = 0; i < SUSPICIOUS_INTENTS.length; i++)
            super.setFeatureValue(i, intentFound[i]);

        return somethingFound.value;
    }

    @Override
    protected void defineFeatures() {
        for (int i = 0; i < SUSPICIOUS_INTENTS.length; i++)
            super.addFeature(FEATURE_PREFIX + SUSPICIOUS_INTENTS[i]);
    }

    private static String FEATURE_PREFIX = "Suspicious Intent Filter: ";

    private static SmaliMemberName ADD_ACTION = new SmaliMemberName("Landroid/content/IntentFilter->addAction");

    private static String[] SUSPICIOUS_INTENTS = new String[] {
            "AIRPLANE_MODE_CHANGED",
            "BOOT_COMPLETED",
            "CONFIGURATION_CHANGED",
            "BATTERY_CHANGED",
            "DEVICE_STORAGE_LOW",
            "DOCK_EVENT",
            "EXTERNAL_APPLICATIONS_AVAILABLE",
            "MANAGE_PACKAGE_STORAGE",
            "MEDIA_MOUNTED",
            "MY_PACKAGE_REPLACED",
            "NEW_OUTGOING_CALL",
            "PACKAGE_ADDED",
            "PACKAGE_CHANGED",
            "PACKAGE_DATA_CLEARED",
            "PACKAGE_FIRST_LAUNCH",
            "PACKAGE_INSTALL",
            "PACKAGE_REMOVED",
            "PACKAGE_REPLACED",
            "PACKAGE_RESTARTED",
            "POWER_CONNECTED",
            "PROVIDER_CHANGED",
            "REBOOT",
            "SHUTDOWN",
            "USER_PRESENT"
    };
}
