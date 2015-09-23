package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import it.polimi.elet.necst.heldroid.ransomware.text.FileClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MultiResourceScanner extends ResourceScanner {
    private List<ResourceScanner> internalScanners;

    public MultiResourceScanner(TextClassifierCollection classifierCollection) {
        super(classifierCollection);
        this.internalScanners = new ArrayList<ResourceScanner>();
    }

    @Override
    protected TextClassification findRansomwareText() {
        TextClassification finalClassification = TextClassification.empty();        
        FileClassification finalFileClassification = new FileClassification();
        
        for (ResourceScanner scanner : internalScanners) {
        	scanner.getFileClassification().clear();
            AcceptanceStrategy.Result result = scanner.evaluate();
            finalClassification.append(scanner.textClassification);
            
            // merge results
            finalFileClassification.merge(result.getFileClassification());
        }
        
        
        finalClassification.setFileClassification(finalFileClassification);
        return finalClassification;
    }

    @Override
    public void setUnpackedApkDirectory(File unpackedApkDirectory) {
        super.setUnpackedApkDirectory(unpackedApkDirectory);
        for (ResourceScanner scanner : internalScanners)
            scanner.setUnpackedApkDirectory(unpackedApkDirectory);
    }

    @Override
    public void setAcceptanceStrategy(AcceptanceStrategy acceptanceStrategy) {
        super.setAcceptanceStrategy(acceptanceStrategy);
        for (ResourceScanner scanner : internalScanners)
            scanner.setAcceptanceStrategy(acceptanceStrategy);
    }


    public List<ResourceScanner> getScanners() {
        return internalScanners;
    }

    public void add(ResourceScanner scanner) {
        this.internalScanners.add(scanner);
    }
}
