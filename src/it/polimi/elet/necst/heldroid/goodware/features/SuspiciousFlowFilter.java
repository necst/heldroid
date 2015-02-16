package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliInspector;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.util.Arrays;
import java.util.Collection;

public class SuspiciousFlowFilter extends FeatureGatherer {
    private SmaliLoader loader;
    private SmaliInspector inspector;

    private Collection<SmaliClass> activities;
    private Collection<SmaliClass> services;
    private SmaliClass smsReceiver;

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_DATA);
        super.addFeature(FEATURE_SMS);
        super.addFeature(FEATURE_SERVICE);
        super.addFeature(FEATURE_SMS_SEND_SMS);
        super.addFeature(FEATURE_SMS_INTERNET);
        super.addFeature(FEATURE_SMS_DB);
    }

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        this.resetFeaturesValues();

        this.loader = applicationData.getSmaliLoader();
        this.inspector = loader.generateInspector();

        return this.performDeepFlowAnalysis();
    }

    private boolean performDeepFlowAnalysis() {
        this.activities = loader.getSubclassesOf(ACTIVITY);
        this.services = loader.getSubclassesOf(SERVICE);

        boolean readsDataAtStartup = false;
        boolean sendsSmsAtStartup = false;
        boolean startsServiceAtStartup = false;
        boolean smsSendSms = false;
        boolean smsSendData = false;
        boolean smsStoreData = false;
        int i = 0;

        if (super.isFeatureEnabled(FEATURE_DATA)) {
            readsDataAtStartup = invokedAtStartup(READ_PHONE_DATA_METHODS);
            super.setFeatureValue(i++, readsDataAtStartup);
        }

        if (super.isFeatureEnabled(FEATURE_SMS)) {
            sendsSmsAtStartup = invokedAtStartup(SEND_TEXT_MESSAGE);
            super.setFeatureValue(i++, sendsSmsAtStartup);
        }

        if (super.isFeatureEnabled(FEATURE_SERVICE)) {
            startsServiceAtStartup = invokedAtStartup(START_SERVICE);
            super.setFeatureValue(i++, startsServiceAtStartup);
        }

        smsReceiver = this.findSmsReceiver();

        if (smsReceiver != null) {
            SmaliMethod onReceive = smsReceiver.getMethodByName(ON_RECEIVE);

            if (onReceive != null) {
                if (super.isFeatureEnabled(FEATURE_SMS_SEND_SMS))
                    smsSendSms = inspector.is(SEND_TEXT_MESSAGE).reachableFrom(onReceive);

                if (super.isFeatureEnabled(FEATURE_SMS_INTERNET))
                    smsSendData = inspector.isAnyClass(Arrays.asList(HTTP_CLIENT, HTTP_POST, HTTP_GET)).reachableFrom(onReceive);

                if (super.isFeatureEnabled(FEATURE_SMS_DB))
                    smsStoreData = inspector.isAnyClass(Arrays.asList(CURSOR, SQLITE_DATABASE)).reachableFrom(onReceive);
            }
        }

        super.setFeatureValue(i++, smsSendSms);
        super.setFeatureValue(i++, smsSendData);
        super.setFeatureValue(i++, smsStoreData);

        return readsDataAtStartup | sendsSmsAtStartup | startsServiceAtStartup | smsSendSms | smsSendData | smsStoreData;
    }

    private boolean invokedAtStartup(SmaliMemberName methodName) {
        return invokedAtStartup(inspector.is(methodName));
    }

    private boolean invokedAtStartup(Collection<SmaliMemberName> methodNames) {
        return invokedAtStartup(inspector.isAny(methodNames));
    }

    private boolean invokedAtStartup(SmaliInspector.Inspection isApi) {
        return
                isApi.reachableFromAny(activities, ON_CREATE) ||
                        isApi.reachableFromAny(services, ON_CREATE_SERVICE) ||
                        isApi.reachableFromAny(activities, ON_START) ||
                        isApi.reachableFromAny(activities, ON_RESTART);
    }

    private SmaliClass findSmsReceiver() {
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        for (SmaliClass klass : loader.getSubclassesOf(BROADCAST_RECEIVER)) {
            String klassSimpleName = klass.getName().getSimpleName();

            if (klassSimpleName.toLowerCase().contains("sms"))
                return klass;

            final Wrapper<Boolean> readsPdus = new Wrapper<Boolean>(false);

            // pdus is the name of the field in the extra attribute of a bundle that contains sms bodies
            // only used in sms receivers
            constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
                @Override
                public boolean constantFound(String value) {
                    value = value.replace("\"", "");

                    if (value.equals("pdus")) {
                        readsPdus.value = true;
                        return true;
                    }

                    return false;
                }
            });

            constantFinder.searchAllLiterals(klass);

            if (readsPdus.value)
                return klass;
        }

        return null;
    }


    private static final String FEATURE_DATA = "Reads phone data at startup";
    private static final String FEATURE_SMS = "Sends SMS at startup"; // TODO: remove
    private static final String FEATURE_SERVICE = "Starts service at startup";
    private static final String FEATURE_SMS_SEND_SMS = "Sends SMS when receiving SMS"; // TODO: remove
    private static final String FEATURE_SMS_INTERNET = "Sends data to a remote page when receiving SMS"; // TODO: remove
    private static final String FEATURE_SMS_DB = "Accesses a database when receiving SMS"; // TODO: remove


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

    private static final SmaliMemberName ON_RECEIVE = new SmaliMemberName("Landroid/content/BroadcastReceiver;->onReceive");

    private static final SmaliMemberName ON_CREATE_SERVICE = new SmaliMemberName("Landroid/app/Service;->onCreate");
    private static final SmaliMemberName ON_CREATE = new SmaliMemberName("Landroid/app/Activity;->onCreate");
    private static final SmaliMemberName ON_START = new SmaliMemberName("Landroid/app/Activity;->onStart");
    private static final SmaliMemberName ON_RESTART = new SmaliMemberName("Landroid/app/Activity;->onRestart");

    private static final SmaliClassName BROADCAST_RECEIVER = new SmaliClassName("Landroid/content/BroadcastReceiver;");
    private static final SmaliClassName ACTIVITY = new SmaliClassName("Landroid/app/Activity;");
    private static final SmaliClassName SERVICE = new SmaliClassName("Landroid/app/Service;");

    private static final SmaliClassName CURSOR = new SmaliClassName("Landroid/database/Cursor;");
    private static final SmaliClassName SQLITE_DATABASE = new SmaliClassName("Landroid/database/sqlite/SQLiteDatabase;");
    private static final SmaliClassName HTTP_CLIENT = new SmaliClassName("Lorg/apache/http/impl/client/DefaultHttpClient;");
    private static final SmaliClassName HTTP_POST = new SmaliClassName("Lorg/apache/http/client/methods/HttpPost;");
    private static final SmaliClassName HTTP_GET = new SmaliClassName("Lorg/apache/http/client/methods/HttpGet;");
}
