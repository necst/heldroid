package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

public class SmsNumbersFilter extends FeatureGatherer {
    private static final String FEATURE_NAME = "Sends SMS to Suspicious Number(s)";
    private static final SmaliMemberName SEND_TEXT_MESSAGE = new SmaliMemberName("Landroid/telephony/SmsManager;->sendTextMessage");
    private static final int SMS_RECEIVER_PARAMETER_INDEX = 0;

    // Numbers starting with #, ##, #*, * or ** are usually employed by carriers to provide
    // instant services such as account balance and account management
    private static final String[] CARRIER_NUMBERS_PREFIXES = { "#", "*" };
    private static final Character ALLOWED_NUMBER_PREFIXE =  '+';

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isFeatureEnabled(FEATURE_NAME))
            return false;

        SmaliLoader loader = applicationData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        final Wrapper<Boolean> suspiciousNumberFound = new Wrapper<Boolean>();
        suspiciousNumberFound.value = false;

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!isPhoneNumber(value))
                    return false;

                if (isSuspiciousNumber(value)) {
                    suspiciousNumberFound.value = true;
                    return true;
                }

                return false;
            }
        });

        constantFinder.searchParameters(SEND_TEXT_MESSAGE, SMS_RECEIVER_PARAMETER_INDEX);

        super.setFeatureValue(0, suspiciousNumberFound.value);

        return suspiciousNumberFound.value;
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_NAME);
    }

    private boolean isPhoneNumber(String literal) {
        boolean prefix = true;
        boolean isNumber = true;

        literal = literal.replace("\"", ""); // purge quotes

        for (Character c : literal.toCharArray()) {
            if (!Character.isDigit(c)) {
                if (prefix && c.equals(ALLOWED_NUMBER_PREFIXE))
                    continue;

                isNumber = false;
                break;
            }

            prefix = false;
        }

        return isNumber;
    }

    private boolean isSuspiciousNumber(String number) {
        boolean isCarrierServiceNumber = false;

        for (String prefix : CARRIER_NUMBERS_PREFIXES)
            if (number.startsWith(prefix)) {
                isCarrierServiceNumber = true;
                break;
            }

        return !isCarrierServiceNumber;
    }
}
