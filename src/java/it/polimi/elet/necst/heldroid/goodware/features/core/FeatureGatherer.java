package it.polimi.elet.necst.heldroid.goodware.features.core;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.*;

public abstract class FeatureGatherer {
    private List<Feature> features;
    private List<Object> defaultValues;
    private Map<String, Boolean> featuresEnabled;

    public enum OperationMode {
        DATA_INSPECTION,
        FILE_ENUMERATION,
        FILE_ANALYSIS,
        NETWORK_QUERY
    }

    public abstract OperationMode getOperationMode();

    public abstract boolean extractFeatures(ApplicationData applicationData);

    public FeatureGatherer() {
        this.clearFeatures();
        this.defineFeatures();
        this.resetFeaturesValues();
        this.enableAllFeatures();
    }

    public Collection<Feature> getFeatures() {
        return features;
    }

    private void clearFeatures() {
        if (features == null)
            features = new ArrayList<Feature>();

        features.clear();
    }

    protected int addFeature(Feature feature) {
        features.add(feature);
        return features.size() - 1;
    }

    protected int addFeature(String name, Object defaultValue) {
        features.add(new Feature(name, defaultValue));
        return features.size() - 1;
    }

    protected int addFeature(String name) {
        features.add(new Feature(name));
        return features.size() - 1;
    }

    protected void setFeatureValue(int index, Object value) {
        features.get(index).setValue(value);
    }

    protected void resetFeaturesValues() {
        for (Feature feature : features)
            feature.setValue(feature.getDefaultValue());
    }

    protected abstract void defineFeatures();

    protected void setAllFeaturesEnabled(boolean enabled) {
        if (featuresEnabled == null)
            featuresEnabled = new HashMap<String, Boolean>();

        for (Feature feature : features)
            featuresEnabled.put(feature.getName(), enabled);
    }

    protected void setFeatureEnabled(String name, boolean enabled) {
        featuresEnabled.put(name, enabled);
    }

    public void enableAllFeatures() {
        this.setAllFeaturesEnabled(true);
    }

    public void disableAllFeatures() {
        this.setAllFeaturesEnabled(false);
    }

    public void enableFeature(String name) {
        this.setFeatureEnabled(name, true);
    }

    public void disableFeature(String name) {
        this.setFeatureEnabled(name, false);
    }

    public boolean isFeatureEnabled(String name) {
        return featuresEnabled.get(name);
    }

    public boolean isFeatureDefined(String name) {
        return featuresEnabled.containsKey(name);
    }

    public boolean isAnyFeatureEnabled(String prefix) {
        for (String key : featuresEnabled.keySet())
            if (featuresEnabled.get(key) == true)
                return true;

        return false;
    }

    public boolean isAnyFeatureEnabled(String... names) {
        for (String name : names)
            if (featuresEnabled.get(name) == true)
                return true;

        return false;
    }
}
