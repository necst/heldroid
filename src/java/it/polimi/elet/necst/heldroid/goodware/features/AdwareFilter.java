package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliInspector;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.io.File;
import java.util.Collection;
import java.util.List;

public class AdwareFilter extends FeatureGatherer {
    private static final String AIRPUSH_CLASS_NAME = "Airpush";

    private ApplicationData applicationData;

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.FILE_ENUMERATION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        this.resetFeaturesValues();
        this.applicationData = applicationData;

        boolean result = this.airpushExists();
        this.checkC2M();
        this.checkNotificationApis();
        this.checkAdClasses();

        return result;
    }

    private boolean airpushExists() {
        if (!super.isFeatureEnabled(FEATURE_AIRPUSH))
            return false;

        File smaliDirectory = applicationData.getDecodedPackage().getSmaliDirectory();
        Collection<File> smaliFiles = applicationData.getDecodedFileTree().getAllFilesIn(smaliDirectory);
        boolean result = false;

        for (File file : smaliFiles)
            if (file.getName().startsWith(AIRPUSH_CLASS_NAME)) {
                result = true;
                break;
            }

        if (result == false) {
            SmaliLoader loader = applicationData.getSmaliLoader();
            SmaliConstantFinder constantFinder = loader.generateConstantFinder();
            final Wrapper<Boolean> airpushUrlFound = new Wrapper<Boolean>(false);

            constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
                @Override
                public boolean constantFound(String value) {
                    if (!value.startsWith("\"")) // not starting with " -> not a string literal
                        return false;

                    if (value.contains(AIRPUSH_URL)) {
                        airpushUrlFound.value = true;
                        return true;
                    }

                    return false;
                }
            });

            result = airpushUrlFound.value;
        }

        super.setFeatureValue(0, result);
        return result;
    }

    private void checkC2M() {
        Collection<String> permissions = applicationData.getManifestReport().getPermissions();
        Collection<String> intents = applicationData.getManifestReport().getIntentFilters();
        int featureIndex = 1;

        for (int i = 0; i < C2M_PERMISSIONS.length; i++) {
            String c2mPermission = C2M_PERMISSIONS[i];

            if (!super.isFeatureEnabled(FEATURE_C2M_PERMISSION_PREFIX + c2mPermission))
                continue;

            boolean present = false;

            for (String permission : permissions)
                if (permission.endsWith(c2mPermission)) {
                    present = true;
                    break;
                }

            super.setFeatureValue(featureIndex++, present);
        }

        for (int i = 0; i < C2M_INTENTS.length; i++) {
            String c2mIntent = C2M_INTENTS[i];

            if (!super.isFeatureEnabled(FEATURE_C2M_INTENT_PREFIX + c2mIntent))
                continue;

            boolean present = false;

            for (String intent : intents)
                if (intent.endsWith(c2mIntent)) {
                    present = true;
                    break;
                }

            super.setFeatureValue(featureIndex++, present);
        }
    }

    private void checkNotificationApis() {
        if (!super.isAnyFeatureEnabled(FEATURE_NOTIFICATION_PREFIX))
            return;

        SmaliLoader loader = applicationData.getSmaliLoader();
        SmaliInspector inspector = loader.generateInspector();
        boolean[] invocationFound = inspector.invocationsExist(NOTIFICATION_METHODS);
        int featureIndex = 1 + C2M_PERMISSIONS.length + C2M_INTENTS.length;

        for (int j = 0; j < NOTIFICATION_METHODS.size(); j++)
            super.setFeatureValue(featureIndex + j, invocationFound[j]);
    }

    private void checkAdClasses() {
        if (!super.isFeatureEnabled(FEATURE_AD_CLASS))
            return;

        SmaliLoader loader = applicationData.getSmaliLoader();
        int featureIndex = 1 + C2M_PERMISSIONS.length + C2M_INTENTS.length + NOTIFICATION_METHODS.size();
        int adClasses = 0;

        for (SmaliClass klass : loader.getClasses()) {
            String name = klass.getName().getSimpleName();

            // Follows Java naming conventions (eg. AdView, AdMob, etc..)
            if (name.length() > 2 && name.startsWith("Ad") && Character.isUpperCase(name.charAt(2)))
                adClasses++;
        }

        super.setFeatureValue(featureIndex, adClasses);
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_AIRPUSH);

        for (int i = 0; i < C2M_PERMISSIONS.length; i++)
            super.addFeature(FEATURE_C2M_PERMISSION_PREFIX + C2M_PERMISSIONS[i]);

        for (int i = 0; i < C2M_INTENTS.length; i++)
            super.addFeature(FEATURE_C2M_INTENT_PREFIX + C2M_INTENTS[i]);

        for (int i = 0; i < NOTIFICATION_METHODS.size(); i++)
            super.addFeature(FEATURE_NOTIFICATION_PREFIX + NOTIFICATION_METHODS.get(i).getCompleteName());

        super.addFeature(FEATURE_AD_CLASS);
    }

    private static final String FEATURE_AIRPUSH = "Airpush Included";
    private static final String FEATURE_C2M_PERMISSION_PREFIX = "C2M Permission: ";
    private static final String FEATURE_C2M_INTENT_PREFIX = "C2M Intent: ";
    private static final String FEATURE_NOTIFICATION_PREFIX = "Notification Api Call: ";
    private static final String FEATURE_AD_CLASS = "Classes with Ad prefix";

    private static final String AIRPUSH_URL = "airpush.com";

    private static final String[] C2M_PERMISSIONS = {
            "c2dm.permission.RECEIVE",
            "C2D_MESSAGE",
            "c2dm.permission.SEND"
    };

    private static final String[] C2M_INTENTS = {
            "c2dm.intent.RECEIVE",
            "c2dm.intent.REGISTRATION",
            "c2dm.intent.REGISTER"
    };

    private static final List<SmaliMemberName> NOTIFICATION_METHODS = SmaliMemberName.newList(
            "Landroid/support/v4/app/NotificationCompat.Builder;->build",
            "Landroid/app/Notification;-><init>",
            "Landroid/app/NotificationManager;->notify",
            "Landroid/app/Notification$Builder;-><init>",
            "Landroid/app/Notification$Builder;->setLargeIcon",
            "Landroid/app/Notification$Builder;->setSound"
    );
}
