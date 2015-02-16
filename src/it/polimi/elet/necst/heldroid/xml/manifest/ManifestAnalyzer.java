package it.polimi.elet.necst.heldroid.xml.manifest;

import it.polimi.elet.necst.heldroid.xml.ParsingException;

import java.io.File;

public interface ManifestAnalyzer {
    ManifestAnalysisReport analyze(File manifestFile) throws ParsingException;
}
