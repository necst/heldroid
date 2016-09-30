package it.polimi.elet.necst.heldroid.csv;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

import java.io.File;
import java.io.IOException;

public class PerformancesWriter extends CsvWriter {
    public PerformancesWriter(File file) throws IOException {
        super(file, true);

        if (file.length() == 0)
            this.writeHeaders();
    }

    protected synchronized void writeHeaders() {
        super.writeField("Apk name");
        super.writeField("Apk size (B)");
        super.writeField("Files count");
        super.writeField("Smali classes count");
        super.writeField("Total smali classes size (B)");
        super.writeField("Unpacking time (s)");
        super.writeField("Analysis time (s)");
        super.writeField("Classification time (ms)");
        super.newRecord();
    }

    public synchronized void writeAll(ApplicationData applicationData, double unpackingTime, double analysisTime, double classificationTime) {
        String apkName = applicationData.getDecodedPackage().getOriginalApk().getAbsolutePath();
        long apkSize = applicationData.getDecodedPackage().getOriginalApk().length();
        long totalClassesSize = applicationData.getSmaliLoader().getTotalClassesSize();
        int filesCount = applicationData.getDecodedFileTree().getAllFiles().size();
        int classesCount = applicationData.getSmaliLoader().getClassesCount();

        super.writeField(apkName);
        super.writeField(apkSize);
        super.writeField(filesCount);
        super.writeField(classesCount);
        super.writeField(totalClassesSize);
        super.writeField(unpackingTime);
        super.writeField(analysisTime);
        super.writeField(classificationTime);
        super.newRecord();
    }
}
