package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.utils.Literal;

import java.util.Collection;

public class PotentialLeakageFilter extends FeatureGatherer {
    private static final String FEATURE_PREFIX_DATA = "Can Steal Data: ";
    private static final String FEATURE_PREFIX_COM = "Communication: ";
    private static final String FEATURE_PREFIX_CONTENT = "Content: ";

    private ApplicationData currentData;

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        this.currentData = applicationData;

        boolean result = this.checkPermissions();
        this.checkContents();

        return result;
    }

    private boolean checkPermissions() {
        Collection<String> permissions = currentData.getManifestReport().getPermissions();
        boolean canReadData = false;
        boolean canSendData = false;
        int featureIndex = 0;

        for (int i = 0; i < SENDING_PERMISSIONS.length; i++) {
            String communicationPermission = SENDING_PERMISSIONS[i];

            if (!super.isFeatureEnabled(FEATURE_PREFIX_COM + communicationPermission))
                continue;

            boolean present = false;

            for (String permission : permissions)
                if (permission.endsWith(communicationPermission)) {
                    present = true;
                    canSendData = true;
                    break;
                }

            super.setFeatureValue(featureIndex++, present);
        }

        for (int i = 0; i < DATA_PERMISSIONS.length; i++) {
            String dataPermission = DATA_PERMISSIONS[i];

            if (!super.isFeatureEnabled(FEATURE_PREFIX_DATA + dataPermission))
                continue;

            boolean present = false;

            for (String permission : permissions)
                if (permission.endsWith(dataPermission)) {
                    present = true;
                    canReadData = true;
                    break;
                }

            super.setFeatureValue(featureIndex++, present);
        }

        return !(canReadData && canSendData);

    }

    private void checkContents() {
        if (!super.isAnyFeatureEnabled(FEATURE_PREFIX_CONTENT))
            return;

        SmaliLoader loader = currentData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();
        final boolean[] contentFound = new boolean[CONTENTS.length];

        for (int i = 0; i < CONTENTS.length; i++)
            contentFound[i] = false;

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!Literal.isString(value))
                    return false;

                value = Literal.getStringValue(value);

                for (int i = 0; i < CONTENTS.length; i++)
                    if (value.startsWith(CONTENTS[i])) {
                        contentFound[i] = true;
                        break;
                    }

                return false;
            }
        });

        constantFinder.searchAllLiterals();

        int featureOffset = SENDING_PERMISSIONS.length + DATA_PERMISSIONS.length;

        for (int i = 0; i < CONTENTS.length; i++)
            super.setFeatureValue(featureOffset + i, contentFound[i]);
    }

    @Override
    protected void defineFeatures() {
        for (int i = 0; i < SENDING_PERMISSIONS.length; i++)
            super.addFeature(FEATURE_PREFIX_COM + SENDING_PERMISSIONS[i]);

        for (int i = 0; i < DATA_PERMISSIONS.length; i++)
            super.addFeature(FEATURE_PREFIX_DATA + DATA_PERMISSIONS[i]);

        for (int i = 0; i < CONTENTS.length; i++)
            super.addFeature(FEATURE_PREFIX_CONTENT + CONTENTS[i]);
    }

    static final String[] SENDING_PERMISSIONS = new String[] {
            "INTERNET",
            "ACCESS_NETWORK_STATE",
            "CHANGE_NETWORK_STATE",
            "BLUETOOTH_ADMIN",
            "BLUETOOTH",
            "WRITE_APN_SETTINGS",
            "NETWORK",
            "SUBSCRIBED_FEEDS_WRITE",
            "NFC",
            "NETWORK_PROVIDER",
            "WRITE_SOCIAL_STREAM",
            "SEND_SMS",
            "USE_SIP"
    };

    static final String[] DATA_PERMISSIONS = new String[] {
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "ACCESS_LOCATION_EXTRA_COMMANDS",
            "ACCESS_MOCK_LOCATION",
            "ACCESS_WIFI_STATE",
            "CAMERA",
            "CAPTURE_AUDIO_OUTPUT",
            "CAPTURE_SECURE_VIDEO_OUTPUT",
            "CAPTURE_VIDEO_OUTPUT",
            "DIAGNOSTIC",
            "DUMP",
            "GET_ACCOUNTS",
            "GET_TASKS",
            "LOCATION_HARDWARE",
            "READ_CALENDAR",
            "READ_CALL_LOG",
            "READ_CONTACTS",
            "READ_EXTERNAL_STORAGE",
            "READ_HISTORY_BOOKMARKS",
            "READ_PHONE_STATE",
            "READ_PROFILE",
            "READ_SMS",
            "READ_SOCIAL_STREAM",
            "READ_SYNC_SETTINGS",
            "RECEIVE_MMS",
            "RECEIVE_SMS",
            "RECORD_AUDIO"
    };

    private static final String[] CONTENTS = new String[] {
            "content://com.android.calendar",
            "content://calendar",
            "content://mms",
            "content://sms",
            "content://com.facebook.katana.provider.AttributionIdProvider",
            "content://telephony/carriers/preferapn",
            "content://media",
    };
}
