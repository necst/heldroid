package it.polimi.elet.necst.heldroid.goodware.features;

import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.SmaliLoader;
import it.polimi.elet.necst.heldroid.utils.Literal;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import java.net.MalformedURLException;
import java.net.URL;

public class SuspiciousUrlsFilter extends FeatureGatherer {
    private static final String FEATURE_HARDCODED_URLS = "Contains Hardcoded URLs";
    private static final String FEATURE_DIFFERENT_DOMAINS = "URLs Domains differ from Package";
    private static final String FEATURE_KNOWN_SUSPIFICOUS_DOMAIN = "Contains URL known to be suspicious";

    private static String[] SUSPICIOUS_DOMAINS = {
            "nowisgame.com",
            "leadbolt.net",
            "leadboltapps.net",
            "searchmobileonline.com",
            "senddroid.com",
            "airpush.com",
            "apsalar.com",
            "adsmogo.net",
            "startappexchange.com"
    };

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_HARDCODED_URLS);
        super.addFeature(FEATURE_DIFFERENT_DOMAINS);
        super.addFeature(FEATURE_KNOWN_SUSPIFICOUS_DOMAIN);
    }

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.DATA_INSPECTION;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (!super.isAnyFeatureEnabled(FEATURE_HARDCODED_URLS, FEATURE_DIFFERENT_DOMAINS, FEATURE_KNOWN_SUSPIFICOUS_DOMAIN))
            return false;

        SmaliLoader loader = applicationData.getSmaliLoader();
        SmaliConstantFinder constantFinder = loader.generateConstantFinder();

        final String packageName = applicationData.getManifestReport().getPackageName();
        final String[] packageParts = packageName.split("\\.");
        final Wrapper<Boolean> containsUrl = new Wrapper<Boolean>(false);
        final Wrapper<Boolean> differentDomains = new Wrapper<Boolean>(false);
        final Wrapper<Boolean> suspiciousDomain = new Wrapper<Boolean>(false);

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (!Literal.isString(value)) // not starting with " -> not a string literal
                    return false;

                String literal = Literal.getStringValue(value); // string literals contain "

                try {
                    URL url = new URL(literal);
                    String host = url.getHost();

                    containsUrl.value = true;

                    if (packageParts.length > 1) {
                        if (!host.endsWith(packageParts[1] + "." + packageParts[0]))
                            differentDomains.value = true;
                    } else if (packageParts.length > 0) {
                        if (!host.endsWith(packageParts[0]))
                            differentDomains.value = true;
                    }

                    for (String sd : SUSPICIOUS_DOMAINS)
                        if (host.endsWith(sd)) {
                            suspiciousDomain.value = true;
                            break;
                        }
                } catch (MalformedURLException e) { }

                return (containsUrl.value && differentDomains.value && suspiciousDomain.value);
            }
        });

        constantFinder.searchAllLiterals();

        super.setFeatureValue(0, containsUrl.value);
        super.setFeatureValue(1, differentDomains.value);
        super.setFeatureValue(2, suspiciousDomain.value);

        return containsUrl.value;
    }
}
