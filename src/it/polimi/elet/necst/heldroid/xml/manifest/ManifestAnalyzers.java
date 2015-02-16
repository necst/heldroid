package it.polimi.elet.necst.heldroid.xml.manifest;

import it.polimi.elet.necst.heldroid.xml.resources.StringResource;

/**
 * Created by Nicolo on 04/02/14.
 */
public class ManifestAnalyzers {
    private static DomManifestAnalyzer domBasedAnalyzer;

    public static ManifestAnalyzer domBased(StringResource stringResource) {
        if (domBasedAnalyzer != null)
            return domBasedAnalyzer;

        domBasedAnalyzer = new DomManifestAnalyzer(stringResource);
        return domBasedAnalyzer;
    }
}
