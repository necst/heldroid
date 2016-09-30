package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;

public abstract class LockingStrategy {
    protected DecodedPackage target;
    private String detectionReport;


    public void setTarget(DecodedPackage target) {
        this.target = target;
    }

    public String getDetectionReport() {
        return detectionReport;
    }

    protected void setDetectionReport(String detectionReport) {
        this.detectionReport = detectionReport;
    }


    public boolean detect() {
        if (target == null)
            throw new NullPointerException("target not set!");

        this.setDetectionReport("");

        return this.detectStrategy();
    }

    protected abstract boolean detectStrategy();
    
    protected abstract String strategyName();
}
