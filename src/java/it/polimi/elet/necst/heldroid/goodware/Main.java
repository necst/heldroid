package it.polimi.elet.necst.heldroid.goodware;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.json.JSONObject;

import it.polimi.elet.necst.heldroid.csv.FeaturesWriter;
import it.polimi.elet.necst.heldroid.csv.PerformancesWriter;
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
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import it.polimi.elet.necst.heldroid.utils.Options;
import it.polimi.elet.necst.heldroid.utils.PersistentFileList;

public class Main {
    public static void printUsage() {
        System.out.println("GoodwareFilter.jar source features-file [-s] [-g] [-c model attributes]");
        System.out.println("source:");
        System.out.println("   an apk file, a directory containing an unpacked apk file, ");
        System.out.println("   a .apklist text file containing a line-by-line list of absolute apk paths");
        System.out.println("   or a directory (which will be recursively searched for any of the above)");
        System.out.println("features-file:");
        System.out.println("   a csv file containing extracted features, and possibly a prediction");
        System.out.println("   if -c is enabled");
        System.out.println("-s: silent mode");
        System.out.println("   Only classifications and critical exceptions are written in output");
        System.out.println("-g: google play mode");
        System.out.println("   Also downloads meta-data from google play store as features");
        System.out.println("-c: classification mode");
        System.out.println("   model is a valid weka model file and attributes an data-empty arff file that");
        System.out.println("   specifies attributes used by the model. Only features whose name is included in");
        System.out.println("   the attribute list are mined");
        System.out.println("-server: server mode");
        System.out.println("   starts a classification http server that receives an apk file as an octet-stream");
        System.out.println("   in a multipart/form-data POST request and returns a json response containing features");
        System.out.println("   and class probabilities. Route to use is /scan. To pass an hash, perform a GET request");
        System.out.println("   to route /hash passing 'hash' as query parameter");
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length < 2) {
            printUsage();
            return;
        }

        mainArgs = args;

        final File target = new File(args[0]);
        Options options = new Options(args);

        classificationEnabled = false;
        if (options.contains("-c")) {
            String[] classifierParams = options.getParameters("-c", 2);
            File model = new File(classifierParams[0]);
            File attributes = new File(classifierParams[1]);
            apkClassifier = new ApkClassifier(model, attributes);
            classificationEnabled = true;
        }

        if (options.contains("-server")) {
            MainServer server = new MainServer(apkClassifier, target);
            server.run();
            return;
        }

        silentMode = options.contains("-s");

        metaFeatureGatherer = new MetaFeatureGatherer();
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
        metaFeatureGatherer.add(new HiddenApkFilter());  // TODO: remove
        metaFeatureGatherer.add(new SmsNumbersFilter()); // TODO: remove
        metaFeatureGatherer.add(new ValidDomainFilter());
        metaFeatureGatherer.add(new SuspiciousFlowFilter());

        if (classificationEnabled) {
            // Only enables used attributes as features to be extracted
            metaFeatureGatherer.disableAllFeatures();
            metaFeatureGatherer.enableFeatures(apkClassifier.getAttributesNames());
        }

        boolean includeGoogle = options.contains("-g");

        if (includeGoogle) {
          System.err.println("WARNING: support for Google Play metadata retrieval has been removed");
            //metaFeatureGatherer.add(new PlayStorePermissionsFilter());
            //metaFeatureGatherer.add(new PlayStorePopularityFilter());
        }

        examinedFiles = new PersistentFileList(new File(EXAMINED_FILES_LIST_NAME));
        featuresWriter = new FeaturesWriter(new File(args[1]), metaFeatureGatherer.getAllFiltersFeatures(), classificationEnabled);
        performancesWriter = new PerformancesWriter(new File(PERFORMANCE_FILENAME));

        availableFiles = new ArrayList<File>();
        availableUnpackedData = new ArrayList<ApplicationData>();
        unpackingTimes = new ArrayList<Double>();

        fileEnumeratingThread = new Thread(new Runnable() {
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

                synchronized (fileEnumerationFinishedLock) {
                    fileEnumerationFinished = true;
                }
            }
        });

        unpackingThread = new Thread(new Runnable() {
            @Override
            public void run() {
                unpackingRoutine();
            }
        });

        analysisThread = new Thread(new Runnable() {
            @Override
            public void run() {
                analysisRoutine();
            }
        });

        fileEnumeratingThread.start();
        unpackingThread.start();
        analysisThread.start();

        fileEnumeratingThread.join();
        unpackingThread.join();
        analysisThread.join();

        closeWriters();
    }

    private static void println(String message) {
        if (!silentMode)
            System.out.println(message);
    }


    private static void enumerateDirectory(File directory) {
        for (File file : directory.listFiles()) {
            if (aborted)
                return;

            checkFile(file);

            if (file.isDirectory())
                enumerateDirectory(file);
        }
    }

    private static void readFileList(File file) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
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

    private static void checkFile(File file) {
        if (examinedFiles.contains(file)) {
            println("Skipped: " + file.getName());
            return;
        }

        if (file.isFile()) {
            synchronized (availableFiles) {
                availableFiles.add(file);
            }
        }
    }

    private static void unpackingRoutine() {
        while (true) {
            if (aborted)
                return;

            int unpackedApksCount;

            synchronized (availableUnpackedData) {
                unpackedApksCount = availableUnpackedData.size();
            }

            if (unpackedApksCount >= MAX_ALLOWED_UNPACKED_APKS_IN_MEMORY) {
                analysisStalls++;

                if (analysisStalls >= MAX_ANALYSIS_STALLS) {
                    println("Stalled " + analysisStalls + " times. Maybe analysis thread crahsed? Restarting.");
                    restartApplication();
                    return;
                }

                try {
                    println("Analysis too slow: unpacking routine stalled for " + UNPACKING_WAIT_TIME + " seconds");
                    Thread.sleep(UNPACKING_WAIT_TIME * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    continue;
                }
            } else {
                analysisStalls = 0;
            }

            File file;

            synchronized (availableFiles) {
                synchronized (fileEnumerationFinishedLock) {
                    if (fileEnumerationFinished && (availableFiles.size() == 0))
                        break;
                }

                if (availableFiles.size() == 0)
                    continue;

                file = availableFiles.get(0);
            }

            println("Unpacking: " + file.getName());

            try {
                Long startTime = System.currentTimeMillis();
                ApplicationData applicationData = ApplicationData.open(file);
                Long endTime = System.currentTimeMillis();

                synchronized (availableUnpackedData) {
                    availableUnpackedData.add(applicationData);
                    unpackingTimes.add((double)(endTime - startTime) / 1000.0);
                }

                println("Unpacked: " + file.getName());
            } catch (Exception e) {
                println("Dropped: " + file.getName() + "; " + e.getMessage());
            }

            synchronized (availableFiles) {
                availableFiles.remove(0);
            }
        }
    }

    private static void analysisRoutine() {
        while (true) {
            if (aborted)
                return;

            ApplicationData applicationData;
            Double unpackingTime;

            synchronized (availableUnpackedData) {
                if (availableUnpackedData.size() == 0) {
                    synchronized (availableFiles) {
                        synchronized (fileEnumerationFinishedLock) {
                            if (fileEnumerationFinished && (availableFiles.size() == 0))
                                break;
                            else
                                continue;
                        }
                    }
                }

                applicationData = availableUnpackedData.get(0);
                unpackingTime = unpackingTimes.get(0);
            }

            scanData(applicationData, unpackingTime);

            synchronized (availableUnpackedData) {
                availableUnpackedData.remove(0);
                unpackingTimes.remove(0);
            }
        }
    }


    private static void scanData(final ApplicationData applicationData, Double unpackingTime) {
        String apkName = applicationData.getDecodedPackage().getOriginalApk().getAbsolutePath();
        println("Submitted: " + apkName);

        Long startTime = System.currentTimeMillis();
        metaFeatureGatherer.matchAllFilters(applicationData);
        Long endTime = System.currentTimeMillis();

        Collection<Feature> features = metaFeatureGatherer.getAllFiltersFeatures();
        Double detectionRatio = checkAnalysisDetectionRatio(applicationData.getDecodedPackage().getOriginalApk());
        Double analysisTime = (double)(endTime - startTime) / 1000.0;
        Double classificationTime = 0.0;
        String predictedClass = "";

        if (classificationEnabled) {
            startTime = System.nanoTime();
            predictedClass = apkClassifier.classify(features);
            endTime = System.nanoTime();
            classificationTime = (double)(endTime - startTime) / 1e+6;
            System.out.println(apkName + " classified as " + predictedClass); // not affected by silent mode
        }
        featuresWriter.writeAll(apkName, features, detectionRatio, predictedClass);
        performancesWriter.writeAll(applicationData, unpackingTime, analysisTime, classificationTime);

        examinedFiles.add(applicationData.getDecodedPackage().getOriginalApk());

        // This process often takes time but is unimportant to the computation's end
        Thread disposeThread = new Thread(new Runnable() {
            @Override
            public void run() {
                applicationData.dispose();
            }
        });
        disposeThread.run();

        println("Completed: " + apkName);
    }

    private static Double checkAnalysisDetectionRatio(File apkFile) {
        File directory = apkFile.getParentFile();
        File vtResult = new File(directory, VT_RESULT_FILENAME);

        if (!vtResult.exists())
            return null;

        try {
            String jsonContent = FileSystem.readFileAsString(vtResult);
            JSONObject vtAnalysis = new JSONObject(jsonContent);
            JSONObject scans = vtAnalysis.getJSONObject("scans");
            int detectionCount = 0;
            int totalScans = 0;

            Iterator<?> iterator = scans.keys();
            while (iterator.hasNext()) {
                String key = (String) iterator.next();
                Object field = scans.get(key);

                if (field instanceof JSONObject) {
                    JSONObject scan = (JSONObject)field;
                    Boolean detected = scan.getBoolean("detected");

                    totalScans++;

                    if (detected)
                        detectionCount++;
                }
            }

            return ((double)detectionCount / totalScans);
        } catch (Exception e) {
            return null;
        }
    }

    private static void closeWriters() throws IOException {
        featuresWriter.close();
        performancesWriter.close();
        examinedFiles.dispose();
    }


    public static void restartApplication()
    {
        synchronized (fileEnumerationFinishedLock) {
            fileEnumerationFinished = true;
        }

        synchronized (availableFiles) {
            availableFiles.clear();
        }

        synchronized (availableUnpackedData) {
            availableUnpackedData.clear();
        }

        aborted = true; // not important to synchronize it

        try {
            closeWriters();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
            File currentJar = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            List<String> commands = new ArrayList<String>();

            commands.add(javaBin);
            commands.add("-jar");
            commands.add(currentJar.getPath());

            for (int i = 0; i < mainArgs.length; i++)
                commands.add(mainArgs[i]);

            final ProcessBuilder builder = new ProcessBuilder(commands);
            builder.start();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.exit(-1);
        }
    }

    private static final String EXAMINED_FILES_LIST_NAME = "examined.txt";
    private static final String VT_RESULT_FILENAME = "vt_result.json";
    private static final String PERFORMANCE_FILENAME = "diagnostics.csv";

    // Maximum allowed number of unpacked applications that can reside as an ApplicationData class in memory
    // When this number is reached, the unpacking thread waits for UNPACKING_WAIT_TIME before continuing
    private static final int MAX_ALLOWED_UNPACKED_APKS_IN_MEMORY = 15;
    private static final int UNPACKING_WAIT_TIME = 5; // seconds

    // Maximum number of times analysis can stall: beyond this, the program assumes the analysis thread has
    // crashed and restarts
    private static final int MAX_ANALYSIS_STALLS = 36; // 36 = 3 minutes
    private static int analysisStalls = 0;

    private static Object fileEnumerationFinishedLock = new Object();
    private static Boolean fileEnumerationFinished = false;
    private static Boolean aborted = false;

    private static Boolean silentMode = false;

    private static boolean classificationEnabled;
    private static ApkClassifier apkClassifier;

    private static MetaFeatureGatherer metaFeatureGatherer;
    private static FeaturesWriter featuresWriter;
    private static PerformancesWriter performancesWriter;
    private static PersistentFileList examinedFiles;

    private static List<File> availableFiles;
    private static List<ApplicationData> availableUnpackedData;
    private static List<Double> unpackingTimes;  // list of times required to unpack an apk

    private static Thread fileEnumeratingThread, unpackingThread, analysisThread;
    private static String[] mainArgs;
}
