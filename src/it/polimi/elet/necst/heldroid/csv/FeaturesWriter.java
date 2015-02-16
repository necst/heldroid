package it.polimi.elet.necst.heldroid.csv;

import it.polimi.elet.necst.heldroid.goodware.features.core.Feature;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

public class FeaturesWriter extends CsvWriter {
    private Collection<Feature> features;
    private boolean includeClassPrediction;

    public FeaturesWriter(File file, Collection<Feature> features, boolean includeClassPrediction) throws IOException {
        super(file, true);
        this.features = features;
        this.includeClassPrediction = includeClassPrediction;

        if (file.length() == 0)
            this.writeHeaders();
    }

    protected synchronized void writeHeaders() {
        super.writeField("Apk Name");

        for (Feature feature : features)
            super.writeField(feature.getName());

        super.writeField("Detection Ratio");

        if (includeClassPrediction)
            super.writeField("Class Prediction");

        super.newRecord();
    }

    public synchronized void writeAll(String apkName, Collection<Feature> gatheredFeatures, Double detectionRatio, String predictedClass) {
        if (gatheredFeatures.size() != features.size())
            throw new IllegalArgumentException("Features number doesn't match with header.");

        super.writeField(apkName);

        for (Feature feature : gatheredFeatures)
            super.writeField(feature.getValue());

        if (detectionRatio != null)
            super.writeField(detectionRatio);
        else
            super.writeField(Feature.UNKNOWN_VALUE);

        if (includeClassPrediction)
            super.writeField(predictedClass);

        super.newRecord();
    }
}
