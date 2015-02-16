package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class ValidDomainFilter extends FeatureGatherer {
    private static final String FEATURE_NAME = "Package Domain Exists";

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.NETWORK_QUERY;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isFeatureEnabled(FEATURE_NAME))
            return false;

        String packageName = applicationData.getManifestReport().getPackageName();
        String[] packageParts = packageName.split("\\.");

        if (packageParts.length < 2) {
            super.setFeatureValue(0, false);
            return false;
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(packageParts[1] + "." + packageParts[0]);
            super.setFeatureValue(0, true);
            return true;
        } catch (UnknownHostException uhe) {
            super.setFeatureValue(0, false);
            return false;
        }
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_NAME);
    }
}
