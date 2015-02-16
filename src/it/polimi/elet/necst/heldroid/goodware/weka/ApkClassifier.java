package it.polimi.elet.necst.heldroid.goodware.weka;

import it.polimi.elet.necst.heldroid.goodware.features.core.Feature;
import weka.classifiers.misc.SerializedClassifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;

import java.io.*;
import java.util.*;

public class ApkClassifier {
    private File attributesFile;

    private Map<Attribute, Double[]> discretizedAttributeSplitPoints;
    private Collection<Attribute> discretizedAttributes;
    private Collection<String> attributesNames;

    private SerializedClassifier innerClassifier;
    private Instances dummyDataSet;

    public Collection<String> getAttributesNames() {
        return attributesNames;
    }

    public ApkClassifier(File model, File attributes) throws IOException {
        if (!model.exists() || !attributes.exists())
            throw new FileNotFoundException("Model or attributes files not present.");

        innerClassifier = new SerializedClassifier();
        innerClassifier.setModelFile(model);

        this.attributesFile = attributes;

        this.createDummyDataSet();
    }

    private void createDummyDataSet() throws IOException {
        InputStream stream = new FileInputStream(attributesFile);
        Reader reader = new InputStreamReader(stream);

        this.dummyDataSet = new Instances(reader);
        this.dummyDataSet.setClassIndex(dummyDataSet.numAttributes() - 1);

        this.discretizedAttributes = new HashSet<Attribute>();
        this.attributesNames = new ArrayList<String>();

        for (int i = 0; i < dummyDataSet.numAttributes(); i++) {
            Attribute a = dummyDataSet.attribute(i);

            if (a.value(0).contains("-inf"))
                discretizedAttributes.add(a);

            attributesNames.add(a.name());
        }
    }

    private Instance createInstance(Collection<Feature> features) {
        if (features.size() < dummyDataSet.numAttributes())
            throw new RuntimeException("Wrong number of core provided.");

        Instance result = new DenseInstance(dummyDataSet.numAttributes());
        result.setDataset(dummyDataSet);

        for (int i = 0; i < dummyDataSet.numAttributes(); i++)
        {
            Attribute attribute = dummyDataSet.attribute(i);
            String attributeName = attribute.name();

            for (Feature feature : features)
                if (feature.getName().equals(attributeName)) {
                    String strValue = feature.getValue().toString();

                    if (strValue.equals(Feature.UNKNOWN_VALUE)) {
                        result.setMissing(i);
                        break;
                    }

                    if (!discretizedAttributes.contains(attribute)) {
                        if (attribute.isNumeric())
                            result.setValue(i, Double.parseDouble(strValue));
                        else
                            result.setValue(i, strValue);
                    } else {
                        Double value = Double.valueOf(strValue);
                        result.setValue(i, discretize(attribute, value));
                    }
                }
        }

        return result;
    }

    private String discretize(Attribute binnedAttribute, double value) {
        if (discretizedAttributeSplitPoints == null)
            discretizedAttributeSplitPoints = new HashMap<Attribute, Double[]>();

        Double[] splitPoints;

        if (discretizedAttributeSplitPoints.containsKey(binnedAttribute)) {
            splitPoints = discretizedAttributeSplitPoints.get(binnedAttribute);
        } else {
            splitPoints = new Double[binnedAttribute.numValues()];
            int j = 0;

            for (int i = 0; i < binnedAttribute.numValues(); i++) {
                String bin = binnedAttribute.value(i);
                Double upperBound = parseUpperBound(bin);

                splitPoints[j++] = upperBound;
            }

            discretizedAttributeSplitPoints.put(binnedAttribute, splitPoints);
        }

        for (int i = 0; i < binnedAttribute.numValues(); i++)
            if (value <= splitPoints[i])
                return binnedAttribute.value(i);

        return binnedAttribute.value(binnedAttribute.numValues() - 1);
    }

    private Double parseUpperBound(String bin) {
        StringBuilder builder = new StringBuilder();

        for (Character c : bin.toCharArray())
            if (c == '\'' || c == '(' || c == ')' || c == '[' || c == ']')
                continue;
            else
                builder.append(c);

        String cleanedBin = builder.toString();
        String[] bounds = cleanedBin.split("\\-");
        String upperBound = bounds[bounds.length - 1];

        if (upperBound.equals("inf"))
            return Double.POSITIVE_INFINITY;

        return Double.valueOf(upperBound);
    }

    public String classify(Collection<Feature> features) {
        Instance instance = this.createInstance(features);

        try {
            double predictedClass = innerClassifier.classifyInstance(instance);
            return dummyDataSet.classAttribute().value((int)predictedClass);
        } catch (Exception e) {
            e.printStackTrace();
            return Feature.UNKNOWN_VALUE;
        }
    }

    public double[] computeDistribution(Collection<Feature> features) {
        Instance instance = this.createInstance(features);

        try {
            return innerClassifier.distributionForInstance(instance);
        } catch (Exception e) {
            e.printStackTrace();
            return new double[0];
        }
    }

    public String getClassLabelFromIndex(double index) {
        return dummyDataSet.classAttribute().value((int)index);
    }

    public String[] getClassLabels() {
        int count = dummyDataSet.classAttribute().numValues();
        String[] classes = new String[count];

        for (int i = 0; i < count; i++)
            classes[i] = this.getClassLabelFromIndex(i);

        return classes;
    }
}
