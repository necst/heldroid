package it.polimi.elet.necst.heldroid.goodware.features.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class FeatureCollection {
    public static Collection<Feature> singleton(Feature feature) {
        List<Feature> list = new ArrayList<Feature>();
        list.add(feature);
        return list;
    }

    public static Collection<Feature> singleton(String name, Object value) {
        return singleton(new Feature(name, value));
    }

    public static Collection<Feature> build(Feature... features) {
        List<Feature> list = new ArrayList<Feature>();

        for (Feature f : features)
            list.add(f);

        return list;
    }

    public static Collection<Feature> map(String[] names, Object[] values) {
        if (names.length != values.length)
            throw new IndexOutOfBoundsException("Names and Values must have the same length, you fool!");

        List<Feature> featureList = new ArrayList<Feature>();

        for (int i = 0; i < names.length; i++)
            featureList.add(new Feature(names[i], values[i]));

        return featureList;
    }
}
