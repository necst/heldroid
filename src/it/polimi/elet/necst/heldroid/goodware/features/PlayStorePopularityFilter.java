package it.polimi.elet.necst.heldroid.goodware.features;

import com.gc.android.market.api.model.Market.App;
import it.polimi.elet.necst.heldroid.goodware.features.core.FeatureGatherer;
import it.polimi.elet.necst.heldroid.goodware.markets.GooglePlayStore;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class PlayStorePopularityFilter extends FeatureGatherer {
    private static volatile Map<String, Collection<App>> popularAppsByCategory;

    private GooglePlayStore store;
    private boolean topCategoryAnalysisEnabled;
    private int topCount;

    public PlayStorePopularityFilter() {
        this.setTopCount(100);
        this.setTopCategoryAnalysisEnabled(false);
        this.store = new GooglePlayStore();
    }

    @Override
    public OperationMode getOperationMode() {
        return OperationMode.NETWORK_QUERY;
    }

    @Override
    public synchronized boolean extractFeatures(ApplicationData applicationData) {
        super.resetFeaturesValues();

        if (popularAppsByCategory == null) {
            popularAppsByCategory = new HashMap<String, Collection<App>>();
        }

        String packageName = applicationData.getManifestReport().getPackageName();

        boolean popular = isPopular(packageName);
        boolean top = isTop(packageName);

        return popular || top;
    }

    private boolean isPopular(String packageName) {
        store.setExtendedInfo(true);

        App target = store.findPackage(packageName);
        boolean result = false;

        if (target != null) {
            if (Float.valueOf(target.getRating()) >= MIN_RATING && target.getRatingsCount() >= MIN_RATING_COUNT)
                result = true;

            if (target.getExtendedInfo().getDownloadsCount() >= MIN_DOWNLOADS_COUNT)
                result = true;

            super.setFeatureValue(0, target.getRating());
            super.setFeatureValue(1, target.getRatingsCount());
            super.setFeatureValue(2, target.getExtendedInfo().getDownloadsCount());
        }
        else {
            super.setFeatureValue(0, 0);
            super.setFeatureValue(1, 0);
            super.setFeatureValue(2, 0);
        }

        return result;
    }

    private boolean isTop(String packageName) {
        if (this.isTopCategoryAnalysisEnabled()) {
            store.setExtendedInfo(false);
            store.setDefaultEntriesCount(this.getTopCount());

            for (String category : GooglePlayStore.APP_CATEGORIES) {
                if (!popularAppsByCategory.containsKey(category)) {
                    popularAppsByCategory.put(category, store.searchByCategory(category));
                }

                int rank = 1;

                for (App app : popularAppsByCategory.get(category)) {
                    if (app.getPackageName().equals(packageName)) {
                        super.setFeatureValue(3, category);
                        super.setFeatureValue(4, rank);
                        return true;
                    }
                    rank++;
                }
            }
        }

        super.setFeatureValue(3, "");
        super.setFeatureValue(4, Integer.MAX_VALUE);
        return false;
    }

    public int getTopCount() {
        return topCount;
    }

    public void setTopCount(int value) {
        if (value > 0)
            this.topCount = value;
    }

    @Override
    protected void defineFeatures() {
        super.addFeature(FEATURE_RATING);
        super.addFeature(FEATURE_RATINGS_COUNT);
        super.addFeature(FEATURE_DOWNLOADS);
        super.addFeature(FEATURE_TOP_CATEGORY);
        super.addFeature(FEATURE_TOP_POSITION);
    }

    public boolean isTopCategoryAnalysisEnabled() {
        return topCategoryAnalysisEnabled;
    }

    public void setTopCategoryAnalysisEnabled(boolean value) {
        this.topCategoryAnalysisEnabled = value;
    }

    private static final String FEATURE_RATING = "Google Play Rating";
    private static final String FEATURE_RATINGS_COUNT = "Google Play Ratings Count";
    private static final String FEATURE_DOWNLOADS = "Google Play Downloads";
    private static final String FEATURE_TOP_POSITION = "Google Play Category Ranking";
    private static final String FEATURE_TOP_CATEGORY = "Google Play Category";

    private static final float MIN_RATING = 4.0f;
    private static final int MIN_RATING_COUNT = 500;
    private static final int MIN_DOWNLOADS_COUNT = 10000;

}
