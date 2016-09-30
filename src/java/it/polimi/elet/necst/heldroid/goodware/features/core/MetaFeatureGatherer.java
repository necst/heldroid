package it.polimi.elet.necst.heldroid.goodware.features.core;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MetaFeatureGatherer {
    private static final int MAX_THREAD_COUNT = 11;
    private static final int MAX_TIMEOUT = 7;

    private List<FeatureGatherer> filters;
    private List<FeatureGatherer> dataInspectionFilters, fileEnumerationFilters, fileAnalysisFilters, networkQueryFilters;

    public Collection<FeatureGatherer> getFilters() {
        return filters;
    }

    public MetaFeatureGatherer() {
        filters = new ArrayList<FeatureGatherer>();
        dataInspectionFilters = new ArrayList<FeatureGatherer>();
        fileEnumerationFilters = new ArrayList<FeatureGatherer>();
        fileAnalysisFilters = new ArrayList<FeatureGatherer>();
        networkQueryFilters = new ArrayList<FeatureGatherer>();

    }

    public void add(FeatureGatherer filter) {
        filters.add(filter);

        switch (filter.getOperationMode()) {
            case DATA_INSPECTION:
                dataInspectionFilters.add(filter);
                break;

            case FILE_ENUMERATION:
                fileEnumerationFilters.add(filter);
                break;

            case FILE_ANALYSIS:
                fileAnalysisFilters.add(filter);
                break;

            case NETWORK_QUERY:
                networkQueryFilters.add(filter);
                break;
        }
    }

    public void remove(FeatureGatherer filter) {
        filters.remove(filter);

        switch (filter.getOperationMode()) {
            case DATA_INSPECTION:
                dataInspectionFilters.remove(filter);
                break;

            case FILE_ENUMERATION:
                fileEnumerationFilters.remove(filter);
                break;

            case FILE_ANALYSIS:
                fileAnalysisFilters.remove(filter);
                break;

            case NETWORK_QUERY:
                networkQueryFilters.remove(filter);
                break;
        }
    }

    public void enableAllFeatures() {
        for (FeatureGatherer filter : filters)
            filter.enableAllFeatures();
    }

    public void disableAllFeatures() {
        for (FeatureGatherer filter : filters)
            filter.disableAllFeatures();
    }

    public void enableFeatures(Collection<String> featuresNames) {
        for (FeatureGatherer filter : filters)
            for (String name : featuresNames)
                if (filter.isFeatureDefined(name))
                    filter.enableFeature(name);
    }

    public void matchAllFilters(final ApplicationData applicationData) {
        ExecutorService executor = Executors.newFixedThreadPool(MAX_THREAD_COUNT);

        for (final FeatureGatherer networkQueryFilter : networkQueryFilters)
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    networkQueryFilter.extractFeatures(applicationData);
                }
            });

        for (final FeatureGatherer fileAnalysisFilter : fileAnalysisFilters)
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    fileAnalysisFilter.extractFeatures(applicationData);
                }
            });

        for (final FeatureGatherer fileEnumerationFilter : fileEnumerationFilters)
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    fileEnumerationFilter.extractFeatures(applicationData);
                }
            });

        for (final FeatureGatherer dataInspectionFilter : dataInspectionFilters)
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    dataInspectionFilter.extractFeatures(applicationData);
                }
            });

        try {
            executor.shutdown();
            if (!executor.awaitTermination(MAX_TIMEOUT, TimeUnit.SECONDS))
                executor.shutdownNow(); // forces threads termination if they don't end after timeout
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public Collection<Feature> getAllFiltersFeatures() {
        List<Feature> featureList = new ArrayList<Feature>();

        for (FeatureGatherer filter : filters)
            featureList.addAll(filter.getFeatures());

        return featureList;
    }
}
