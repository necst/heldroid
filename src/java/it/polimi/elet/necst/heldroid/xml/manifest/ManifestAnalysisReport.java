package it.polimi.elet.necst.heldroid.xml.manifest;

import java.util.Collection;

public interface ManifestAnalysisReport {
    String getPackageName();
    String getApplicationName();
    String getApplicationDescription();
    Collection<String> getPermissions();
    Collection<String> getIntentFilters();
    Collection<String> getUsedFeatures();
}
