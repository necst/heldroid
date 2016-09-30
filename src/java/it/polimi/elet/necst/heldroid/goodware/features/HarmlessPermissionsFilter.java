package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.Collection;

public class HarmlessPermissionsFilter extends FeatureGatherer {
    private static final String FEATURE_PREFIX = "Harmless Permission: ";

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        Collection<String> permissions = applicationData.getManifestReport().getPermissions();
        boolean result = false;

        for (int i = 0; i < HARMLESS_PERMISSIONS.length; i++) {
            String harmlessPermission = HARMLESS_PERMISSIONS[i];

            if (!super.isFeatureEnabled(FEATURE_PREFIX + harmlessPermission))
                continue;

            boolean permissionPresent = false;

            for (String permission : permissions)
                if (permission.endsWith(harmlessPermission)) {
                    permissionPresent = true;
                    result = true;
                    break;
                }

            super.setFeatureValue(i, permissionPresent);
        }

        return result;
    }

    @Override
    protected void defineFeatures() {
        for (int i = 0; i < HARMLESS_PERMISSIONS.length; i++)
            super.addFeature(FEATURE_PREFIX + HARMLESS_PERMISSIONS[i]);
    }

    static final String[] HARMLESS_PERMISSIONS = new String[] {
            "ACCESS_SURFACE_FLINGER",
            "ACCOUNT_MANAGER",
            "ADD_VOICEMAIL",
            "CONTROL_LOCATION_UPDATES",
            "DEVICE_POWER",
            "EXPAND_STATUS_BAR",
            "FLASHLIGHT",
            "FORCE_BACK",
            "GET_PACKAGE_SIZE",
            "GET_TOP_ACTIVITY_INFO",
            "GLOBAL_SEARCH",
            "INSTALL_SHORTCUT",
            "MANAGE_DOCUMENTS",
            "MEDIA_CONTENT_CONTROL",
            "MODIFY_AUDIO_SETTINGS",
            "READ_USER_DICTIONARY",
            "REORDER_TASKS",
            "SEND_RESPOND_VIA_MESSAGE",
            "SET_ALARM",
            "SET_ANIMATION_SCALE",
            "SET_ORIENTATION",
            "SET_POINTER_SPEED",
            "SET_TIME",
            "SET_TIME_ZONE",
            "SET_WALLPAPER",
            "UNINSTALL_SHORTCUT",
            "VIBRATE",
            "WAKE_LOCK",
            "WRITE_CALENDAR",
            "WRITE_CALL_LOG",
            "WRITE_CONTACTS",
            "WRITE_USER_DICTIONARY"
    };
}
