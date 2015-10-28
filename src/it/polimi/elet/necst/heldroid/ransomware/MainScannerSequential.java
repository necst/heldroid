package it.polimi.elet.necst.heldroid.ransomware;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.utils.Options;
import it.polimi.elet.necst.heldroid.utils.PersistentFileList;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import soot.jimple.infoflow.results.InfoflowResults;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionResult;
import it.polimi.elet.necst.heldroid.ransomware.locking.MultiLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.MultiResourceScanner;
import it.polimi.elet.necst.heldroid.utils.Stopwatch;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainScannerSequential {
    public static void main(String[] args) throws ParserConfigurationException, IOException, InterruptedException {
        final File target = new File(args[1]);
        final File result = new File(args[2]);
        final Options options = new Options(args);

        silentMode = options.contains("-s");
        noLock = options.contains("-nl");
        noEncryption = options.contains("-ne");

        multiLockingStrategy = Factory.createLockingStrategy();
        multiResourceScanner = Factory.createResourceScanner();
        encryptionFlowDetector = Factory.createEncryptionFlowDetector();

        examinedFiles = new PersistentFileList(Globals.EXAMINED_FILES_LIST_FILE);

        if (result.exists())
            resultsWriter = new BufferedWriter(new FileWriter(result, true));
        else {
            resultsWriter = new BufferedWriter(new FileWriter(result));
            resultsWriter.write("Sample; LockDetected; TextDetected; TextScore; EncryptionDetected; Comment; TimedOut; FileClassification");
            resultsWriter.newLine();
        }

        if (Globals.PERFORMANCE_FILE.exists())
            performancesWriter = new BufferedWriter(new FileWriter(Globals.PERFORMANCE_FILE, true));
        else {
            performancesWriter = new BufferedWriter(new FileWriter(Globals.PERFORMANCE_FILE));
            performancesWriter.write("Sample, LockDetectionTime, TextDetectionTime, EncryptionDetectionTime, UnpackingTime, SmaliClassCount, SmaliSize, ApkSize");
            performancesWriter.newLine();
        }

        Thread.currentThread().setUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                if ((t != null) && (t.getName() != null))
                    System.out.println("In thread : " + t.getName());

                if ((e != null) && (e.getMessage() != null)) {
                    System.out.println(e.getClass().getName() + ": " + e.getMessage());
                    if (e.getStackTrace() != null)
                        for (StackTraceElement ste : e.getStackTrace())
                            if (ste != null)
                                System.out.println(ste.getFileName() + " at line " + ste.getLineNumber());
                }
            }
        });

        if (target.isDirectory()) {
            enumerateDirectory(target);
        } else {
            String name = target.getName().toLowerCase();

            if (name.endsWith(".apklist"))
                readFileList(target);
            else if (name.endsWith(".apk"))
                checkFile(target);
        }

        closeWriters();
    }

    private static void println(String message) {
        if (!silentMode)
            System.out.println(message);
    }

    private static void print(String message) {
        if (!silentMode)
            System.out.print(message);
    }


    private static void enumerateDirectory(File directory) {
        for (File file : directory.listFiles()) {
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

        if (!file.getName().toLowerCase().endsWith(".apk")) {
            return;
        }

        final Wrapper<Double> unpackingTime = new Wrapper<Double>(0.0);
        final ApplicationData data = unpack(file, unpackingTime);

        if (data == null) {
            return;
        }

        scanData(data, unpackingTime.value);
    }


    private static ApplicationData unpack(final File file, final Wrapper<Double> unpackingTime) {
        final Wrapper<ApplicationData> resultWrapper = new Wrapper<ApplicationData>(null);
        final Wrapper<Exception> exceptionWrapper = new Wrapper<Exception>(null);

        println("Unpacking: " + file.getName());

        unpackingTime.value = Stopwatch.time(new Runnable() {
            @Override
            public void run() {
                try {
                    resultWrapper.value = ApplicationData.open(file);
                } catch (Exception e) {
                    exceptionWrapper.value = e;
                }
            }
        });

        if (resultWrapper.value != null)
            println("Unpacked: " + file.getName());
        else if (exceptionWrapper.value != null)
            println("Dropped: " + file.getName() + " : " + exceptionWrapper.value.getMessage());

        return resultWrapper.value;
    }

    private static void scanData(final ApplicationData applicationData, Double unpackingTime) {
        String apkName = applicationData.getDecodedPackage().getOriginalApk().getAbsolutePath();
        println("Submitted: " + apkName);

        examinedFiles.add(applicationData.getDecodedPackage().getOriginalApk());

        final Wrapper<Boolean> lockDetected = new Wrapper<Boolean>(false);
        final Wrapper<AcceptanceStrategy.Result> textDetected = new Wrapper<AcceptanceStrategy.Result>(AcceptanceStrategy.fail());
        final Wrapper<Boolean> encryptionDetected = new Wrapper<Boolean>(false);
        final Wrapper<Boolean> hasRWPermission = new Wrapper<>(false);
        final Wrapper<Double> lockDetectionTime = new Wrapper<Double>((double)ANALYSIS_TIMEOUT);
        final Wrapper<Double> textDetectionTime = new Wrapper<Double>((double)ANALYSIS_TIMEOUT);
        final Wrapper<Double> encryptionDetectionTime = new Wrapper<Double>((double)ANALYSIS_TIMEOUT);

        ExecutorService executor = Executors.newFixedThreadPool(3);

        executor.submit(new Runnable() {
            @Override
            public void run() {
                Double time = Stopwatch.time(new Runnable() {
                    @Override
                    public void run() {
                        multiResourceScanner.setUnpackedApkDirectory(applicationData.getDecodedPackage().getDecodedDirectory());
                        AcceptanceStrategy.Result result = multiResourceScanner.evaluate();
                        if (textDetected != null)
                            textDetected.value = result;
                    }
                });

                if (textDetectionTime != null)
                    textDetectionTime.value = time;
            }
        });

        if (!noLock)
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    Double time = Stopwatch.time(new Runnable() {
                        @Override
                        public void run() {
                            multiLockingStrategy.setTarget(applicationData.getDecodedPackage());
                            Boolean result = lockDetected.value = multiLockingStrategy.detect();
                            if (lockDetected != null)
                                lockDetected.value = result;
                        }
                    });

                    if (lockDetectionTime != null)
                        lockDetectionTime.value = time;
                }
            });

        if (!noEncryption)
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    Double time = Stopwatch.time(new Runnable() {
                        @Override
                        public void run() {
                            encryptionFlowDetector.setTarget(applicationData.getDecodedPackage());
                            
                            Wrapper<EncryptionResult> encryptionResult = encryptionFlowDetector.detect();
                            InfoflowResults infoFlow = encryptionResult.value.getInfoFlowResults();
                            Boolean result = (infoFlow != null && infoFlow.getResults().size() > 0);
                            if (encryptionDetected != null)
                                encryptionDetected.value = result;
                            if (hasRWPermission != null)
                            	hasRWPermission.value = encryptionResult.value.isWritable();
                        }
                    });

                    if (encryptionDetectionTime != null)
                        encryptionDetectionTime.value = time;
                }
            });

        boolean timedOut = false;
        executor.shutdown();

        try {
            if (!executor.awaitTermination(ANALYSIS_TIMEOUT, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                timedOut = true;
            }
        } catch (InterruptedException e) { }

        try {
            resultsWriter.write(String.format("%s; %b; %b; %f; %b; %b; \"%s\"; %b; %s\n",
                    apkName,
                    lockDetected.value,
                    textDetected.value.isAccepted(),
                    textDetected.value.getScore(),
                    hasRWPermission.value,
                    encryptionDetected.value,
                    textDetected.value.getComment(),
                    timedOut,
                    textDetected.value.getFileClassification()));

            performancesWriter.write(String.format("%s, %f, %f, %f, %f, %d, %d, %d\n",
                    apkName,
                    lockDetectionTime.value,
                    textDetectionTime.value,
                    encryptionDetectionTime.value,
                    unpackingTime,
                    applicationData.getSmaliLoader().getClassesCount(),
                    applicationData.getSmaliLoader().getTotalClassesSize(),
                    applicationData.getDecodedPackage().getOriginalApk().length()));

            resultsWriter.flush();
            performancesWriter.flush();
        } catch (IOException e) { }

        // No longer deleting temp files

        if (!timedOut)
            println("Completed: " + apkName);
        else {
            print("Timeout");

            if (textDetectionTime.value == ANALYSIS_TIMEOUT) print(" TextDetection");
            if (!noLock && (lockDetectionTime.value == ANALYSIS_TIMEOUT)) print(" LockDetection");
            if (!noEncryption && (encryptionDetectionTime.value == ANALYSIS_TIMEOUT)) print(" EncryptionDetection");

            println(": " + apkName);
        }
    }


    private static void closeWriters() throws IOException {
        resultsWriter.close();
        performancesWriter.close();
        examinedFiles.dispose();
    }


    private static final int ANALYSIS_TIMEOUT = 40; // seconds

    private static Boolean silentMode = false;
    private static Boolean noLock = false;
    private static Boolean noEncryption = false;

    private static PersistentFileList examinedFiles;
    private static BufferedWriter resultsWriter;
    private static BufferedWriter performancesWriter;

    private static MultiLockingStrategy multiLockingStrategy;
    private static MultiResourceScanner multiResourceScanner;
    private static EncryptionFlowDetector encryptionFlowDetector;
}
