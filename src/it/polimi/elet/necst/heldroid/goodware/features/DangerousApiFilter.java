package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliInspector;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;

import java.util.Collection;
import java.util.List;

public class DangerousApiFilter extends FeatureGatherer {
    private SmaliLoader loader;
    private SmaliInspector inspector;

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        this.resetFeaturesValues();

        this.loader = applicationData.getSmaliLoader();
        this.inspector = loader.generateInspector();

        boolean result = this.checkDangerousApiExistence();
        this.checkDangerousApiCalls();

        return result;
    }

    private boolean checkDangerousApiExistence() {
        if (!super.isAnyFeatureEnabled(FEATURE_PREFIX))
            return false;

        boolean[] methodsFound = inspector.invocationsExist(DANGEROUS_METHODS);
        boolean result = false;

        for (int i = 0; i < DANGEROUS_METHODS.size(); i++) {
            SmaliMemberName methodName = DANGEROUS_METHODS.get(i);

            boolean found = methodsFound[i];
            super.setFeatureValue(i, found);

            if (found)
                result = true;
        }

        return result;
    }

    private void checkDangerousApiCalls() {
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();
        int i = DANGEROUS_METHODS.size();

        if (super.isFeatureEnabled(FEATURE_TESTS_ADB)) {
            boolean getAdbEnabled = constantFinder.testInvocationParameter(SECURE_GET_INT, 1, ADB_ENABLED);
            super.setFeatureValue(i++, getAdbEnabled);
        }

        if (super.isFeatureEnabled(FEATURE_EDIT_ADB)) {
            boolean setAdbEnabled = constantFinder.testInvocationParameter(SECURE_PUT_INT, 1, ADB_ENABLED);
            super.setFeatureValue(i++, setAdbEnabled);
        }
    }

    @Override
    protected void defineFeatures() {
        for (int i = 0; i < DANGEROUS_METHODS.size(); i++)
            super.addFeature(FEATURE_PREFIX + DANGEROUS_METHODS.get(i).getCompleteName());

        super.addFeature(FEATURE_TESTS_ADB);
        super.addFeature(FEATURE_EDIT_ADB);
    }

    // Taken from http://www.cis.syr.edu/~wedu/Research/paper/Malware_Analysis_2013.pdf
    private static final List<SmaliMemberName> DANGEROUS_METHODS = SmaliMemberName.newList(
            "Landroid/content/Context;->startService",
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getLine1Number",
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
            "Landroid/telephony/TelephonyManager;->getSimOperatorName",
            "Landroid/telephony/TelephonyManager;->getCellLocation",
            "Landroid/telephony/cdma/CdmaCellLocation;->getSystemId",
            "Landroid/telephony/SmsManager;->sendTextMessage",
            "Landroid/content/Intent;->setDataAndType",
            "Landroid/content/Intent;->setType",
            "Landroid/app/ActivityManager;->getRunningServices",
            "Landroid/app/ActivityManager;->getMemoryInfo",
            "Landroid/app/ActivityManager;->restartPackage",
            "Landroid/content/pm/PackageManager;->getInstalledPackages",
            "Ljava/lang/System;->loadLibrary",
            "Ljavax/crypto/Cipher;->getInstance",
            "Landroid/provider/Browser;->getAllBookmarks",
            "Landroid/content/pm/PackageManager;->queryContentProviders",
            "Landroid/content/Intent;->describeContents",
            "Landroid/content/pm/PackageManager;->getPreferredActivities",
            "Landroid/app/Service;->onLowMemory",
            "Landroid/os/Parcel;->marshall",
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ljava/lang/ClassLoader;->loadClass",
            "Landroid/accounts/AccountManager;->getAccounts",
            "Landroid/content/BroadcastReceiver;->abortBroadcast"
    );

    private static final String FEATURE_PREFIX = "Api Call: ";
    private static final String FEATURE_TESTS_ADB = "Checks adb_enabled";
    private static final String FEATURE_EDIT_ADB = "Tries to modify adb_enabled";

    private static Collection<SmaliMemberName> READ_PHONE_DATA_METHODS = SmaliMemberName.newList(
            "Landroid/telephony/TelephonyManager;->getSubscriberId",
            "Landroid/telephony/TelephonyManager;->getDeviceId",
            "Landroid/telephony/TelephonyManager;->getLine1Number",
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
            "Landroid/telephony/TelephonyManager;->getCellLocation",
            "Landroid/telephony/TelephonyManager;->getSimOperatorName",
            "Landroid/accounts/AccountManager->getAccounts",
            "Landroid/provider/Browser;->getAllBookmarks"
    );

    private static final SmaliMemberName SEND_TEXT_MESSAGE = new SmaliMemberName("Landroid/telephony/SmsManager;->sendTextMessage");
    private static final SmaliMemberName START_SERVICE = new SmaliMemberName("Landroid/content/Context;->startService");

    private static final SmaliMemberName SECURE_GET_INT = new SmaliMemberName("Landroid/provider/Settings$Secure->getInt;");
    private static final SmaliMemberName SECURE_PUT_INT = new SmaliMemberName("Landroid/provider/Settings$Secure->putInt;");
    private static final String ADB_ENABLED = "adb_enabled";

}
