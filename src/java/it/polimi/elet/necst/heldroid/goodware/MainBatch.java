/**
 * 
 */
package it.polimi.elet.necst.heldroid.goodware;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;

import it.polimi.elet.necst.heldroid.goodware.features.AdwareFilter;
import it.polimi.elet.necst.heldroid.goodware.features.DangerousApiFilter;
import it.polimi.elet.necst.heldroid.goodware.features.DangerousPermissionsFilter;
import it.polimi.elet.necst.heldroid.goodware.features.FileMetricsFilter;
import it.polimi.elet.necst.heldroid.goodware.features.HarmlessPermissionsFilter;
import it.polimi.elet.necst.heldroid.goodware.features.HiddenApkFilter;
import it.polimi.elet.necst.heldroid.goodware.features.PackageFilter;
import it.polimi.elet.necst.heldroid.goodware.features.PotentialLeakageFilter;
import it.polimi.elet.necst.heldroid.goodware.features.SmsNumbersFilter;
import it.polimi.elet.necst.heldroid.goodware.features.SuspiciousFlowFilter;
import it.polimi.elet.necst.heldroid.goodware.features.SuspiciousIntentFilter;
import it.polimi.elet.necst.heldroid.goodware.features.SuspiciousUrlsFilter;
import it.polimi.elet.necst.heldroid.goodware.features.SystemCallsFilter;
import it.polimi.elet.necst.heldroid.goodware.features.ValidDomainFilter;
import it.polimi.elet.necst.heldroid.goodware.features.core.Feature;
import it.polimi.elet.necst.heldroid.goodware.features.core.MetaFeatureGatherer;
import it.polimi.elet.necst.heldroid.goodware.weka.ApkClassifier;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;

public class MainBatch {
	
	private static ApkClassifier apkClassifier;
	
	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			printUsage();
			return;
		}
		
		final File target = new File(args[0]);
		File destination = new File(args[1]);
		
        File model = new File("hel-models/j48-sensitive-h.model");
        File attributes = new File("hel-models/attributes.arff");
        apkClassifier = new ApkClassifier(model, attributes);
        
        new Thread(new Worker(apkClassifier, target, destination)).start();


	}
	
	public static void printUsage() {
        System.out.println("GoodwareFilter.jar source destination");
        System.out.println("source:");
        System.out.println("   an apk file, a directory containing an unpacked apk file, ");
        System.out.println("   a .apklist text file containing a line-by-line list of absolute apk paths");
        System.out.println("   or a directory (which will be recursively searched for any of the above)");
        System.out.println("destination:");
        System.out.println("   a folder that will contain the output");
    }
	
	static class Worker implements Runnable {
		
		private ApkClassifier sharedClassifier;
		private File uploadDirectory;
		private File hashDirectory;
		private File target;
		private String[] classLabels;

		public Worker(ApkClassifier sharedClassifier, File target, File uploadDirectory) {
			this.sharedClassifier = sharedClassifier;
			this.uploadDirectory = uploadDirectory;
			this.target = target;
			
			if (!uploadDirectory.exists())
	            if (!uploadDirectory.mkdir())
	                throw new RuntimeException("Cannot create upload directory!");

	        this.hashDirectory = new File(uploadDirectory, "hash");

	        if (!hashDirectory.exists())
	            if (!hashDirectory.mkdir())
	                throw new RuntimeException("Cannot create hash directory!");

	        this.classLabels = sharedClassifier.getClassLabels();
		}
		
		/**
		 * {@inheritDoc}
		 */
		@Override
		public void run() {
			if (target.isDirectory()) {
                enumerateDirectory(target);
            } else {
                String name = target.getName().toLowerCase();

                if (name.endsWith(".apklist"))
                    readFileList(target);
                else if (name.endsWith(".apk"))
                    checkFile(target);
            }
		}
		
		private void readFileList(File fileList) {
			try {
	            BufferedReader reader = new BufferedReader(new FileReader(fileList));
	            String line = null;

	            while((line = reader.readLine()) != null) {
	                File readFile = new File(line);

	                if (readFile.exists())
	                    checkFile(readFile);
	            }

	            reader.close();
	        } catch (Exception e) {
	            e.printStackTrace();
	        }

		}
		
		private void enumerateDirectory(File directory) {
			for (File file : directory.listFiles()) {
	            checkFile(file);

	            if (file.isDirectory())
	                enumerateDirectory(file);
	        }

		}
		
		private void checkFile(File file) {
			String result = buildResponseFromScan(file);
			System.out.println(result);
		}
		
		private String buildResponseFromScan(File file) {
	        MetaFeatureGatherer gatherer = this.createGatherer();

	        ApplicationData applicationData;

	        try {
	            applicationData = ApplicationData.open(file);
	        } catch (Exception e) {
	            return "Error unpacking: " + e.getMessage();
	        }

	        gatherer.matchAllFilters(applicationData);
	        applicationData.dispose();

	        Collection<Feature> features = gatherer.getAllFiltersFeatures();
	        String prediction;
	        double[] classDistribution;

	        synchronized (this.sharedClassifier) {
	        	prediction = this.sharedClassifier.classify(features);
	            classDistribution = this.sharedClassifier.computeDistribution(features);
	        }

	        return this.buildResponseFromResults(features, classDistribution, prediction);
	    }
		
		private String buildResponseFromResults(Collection<Feature> features, double[] classDistribution, String prediction) {
	        StringBuilder builder = new StringBuilder();
	        boolean firstLine;

	        builder.append("{\n");
	        builder.append("   \"features\": [\n      ");

	        firstLine = true;
	        for (Feature f : features) {
	            if (!firstLine) builder.append(",\n      ");

	            builder.append(String.format("{ \"name\": \"%s\", value: \"%s\" }", f.getName(), f.getValue()));
	            firstLine = false;
	        }
	        builder.append("\n   ],\n   ");

	        firstLine = true;
	        for (int i = 0; i < classDistribution.length; i++) {
	            if (!firstLine) builder.append(",\n   ");

	            builder.append(String.format("\"%s\": %s", this.classLabels[i], String.valueOf(classDistribution[i])));
	            firstLine = false;
	        }
	        builder.append(",\n   \"prediction\": \"" + prediction + "\"");
	        builder.append("\n}");

	        return builder.toString();
	    }
		
		private MetaFeatureGatherer createGatherer() {
	        MetaFeatureGatherer metaFeatureGatherer = new MetaFeatureGatherer();

	        metaFeatureGatherer.add(new DangerousPermissionsFilter());
	        metaFeatureGatherer.add(new DangerousApiFilter());
	        metaFeatureGatherer.add(new PotentialLeakageFilter());
	        metaFeatureGatherer.add(new AdwareFilter());
	        metaFeatureGatherer.add(new SuspiciousUrlsFilter());
	        metaFeatureGatherer.add(new PackageFilter());
	        metaFeatureGatherer.add(new FileMetricsFilter());
	        metaFeatureGatherer.add(new SystemCallsFilter());
	        metaFeatureGatherer.add(new HarmlessPermissionsFilter());
	        metaFeatureGatherer.add(new SuspiciousIntentFilter());
	        metaFeatureGatherer.add(new HiddenApkFilter());
	        metaFeatureGatherer.add(new SmsNumbersFilter());
	        metaFeatureGatherer.add(new ValidDomainFilter());
	        metaFeatureGatherer.add(new SuspiciousFlowFilter());

	        metaFeatureGatherer.disableAllFeatures();
	        metaFeatureGatherer.enableFeatures(this.sharedClassifier.getAttributesNames());

	        return metaFeatureGatherer;
	    }
	}

}
