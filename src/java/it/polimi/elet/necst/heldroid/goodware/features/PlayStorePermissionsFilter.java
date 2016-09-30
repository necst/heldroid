package it.polimi.elet.necst.heldroid.goodware.features;

import com.gc.android.market.api.model.Market.App;
import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.goodware.markets.GooglePlayStore;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.Collection;
import java.util.List;

public class PlayStorePermissionsFilter extends FeatureGatherer {
    private static final String FEATURE_NAME = "Overprivileged Permissions";
    private GooglePlayStore store;

    public PlayStorePermissionsFilter() {
        store = new GooglePlayStore();
    }

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.NETWORK_QUERY;
    }

    @Override
    public boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        String packageName = applicationData.getManifestReport().getPackageName();
        Collection<String> permissions = applicationData.getManifestReport().getPermissions();

        store.setExtendedInfo(true);

        App app = store.findPackage(packageName);

        if (app == null) {
            super.setFeatureValue(0, 0);
            return false;
        }

        List<String> appPermissions = app.getExtendedInfo().getPermissionIdList();
        int overprivileges = 0;

        for (String permission : permissions)
            if (!appPermissions.contains(permission))
                overprivileges++;

        super.setFeatureValue(0, overprivileges);

        return (overprivileges > 0);
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_NAME);
    }
}
