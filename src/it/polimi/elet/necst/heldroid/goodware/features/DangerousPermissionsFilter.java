package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.Collection;

public class DangerousPermissionsFilter extends FeatureGatherer {
    private static final String FEATURE_PREFIX = "Dangerous Permission: ";

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        Collection<String> permissions = applicationData.getManifestReport().getPermissions();
        boolean result = false;

        for (int i = 0; i < DANGEROUS_PERMISSIONS.length; i++) {
            String dangerousPermission = DANGEROUS_PERMISSIONS[i];

            if (!super.isFeatureEnabled(FEATURE_PREFIX + dangerousPermission))
                continue;

            boolean permissionPresent = false;

            for (String permission : permissions)
                if (permission.endsWith(dangerousPermission)) {
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
        for (int i = 0; i < DANGEROUS_PERMISSIONS.length; i++)
            super.addFeature(FEATURE_PREFIX + DANGEROUS_PERMISSIONS[i]);
    }

    static final String[] DANGEROUS_PERMISSIONS = new String[] {
            "ACCESS_SUPERUSER",
            "BLUETOOTH_PRIVILEGED",
            "BRICK",
            "CHANGE_COMPONENT_ENABLED_STATE",
            "CLEAR_APP_USER_DATA",
            "DELETE_CACHE_FILES",
            "DELETE_PACKAGES",
            "DISABLE_KEYGUARD",
            "FACTORY_TEST",
            "INSTALL_PACKAGES",
            "INJECT_EVENTS",
            "INTERNAL_SYSTEM_WINDOW",
            "KILL_BACKGROUND_PROCESSES",
            "MASTER_CLEAR",
            "MODIFY_PHONE_STATE",
            "MOUNT_FORMAT_FILESYSTEM",
            "MOUNT_UNMOUNT_FILESYSTEM",
            "PROCESS_OUTGOING_CALLS",
            "READ_LOGS",
            "REBOOT",
            "RECEIVE_BOOT_COMPLETED",
            "STATUS_BAR",
            "WRITE_EXTERNAL_STORAGE",
            "WRITE_HISTORY_BOOKMARKS",
            "WRITE_PROFILE",
            "WRITE_SECURE_SETTINGS"
    };
}
