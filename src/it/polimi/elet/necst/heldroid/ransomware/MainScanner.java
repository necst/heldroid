package it.polimi.elet.necst.heldroid.ransomware;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.utils.Options;
import it.polimi.elet.necst.heldroid.utils.PersistentFileList;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.ransomware.locking.MultiLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.MultiResourceScanner;
import it.polimi.elet.necst.heldroid.utils.Stopwatch;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainScanner {
	public static void main(String[] args) throws ParserConfigurationException,
			IOException, InterruptedException {
		mainArgs = args;

		final File target = new File(args[1]);
		final File result = new File(args[2]);
		final Options options = new Options(args);

		silentMode = options.contains("-s");
		noLock = options.contains("-nl");
		noEncryption = options.contains("-ne");
		noTextDetection = options.contains("-nt");

		multiLockingStrategy = Factory.createLockingStrategy();
		multiResourceScanner = Factory.createResourceScanner();
		encryptionFlowDetector = Factory.createEncryptionFlowDetector();

		examinedFiles = new PersistentFileList(
				Globals.EXAMINED_FILES_LIST_FILE);

		if (result.exists())
			resultsWriter = new BufferedWriter(new FileWriter(result, true));
		else {
			resultsWriter = new BufferedWriter(new FileWriter(result));
			resultsWriter.write(
					"Sample; LockDetected; TextDetected; TextScore; EncryptionDetected; Comment; TimedOut; Classified files");
			resultsWriter.newLine();
		}

		if (Globals.PERFORMANCE_FILE.exists())
			performancesWriter = new BufferedWriter(
					new FileWriter(Globals.PERFORMANCE_FILE, true));
		else {
			performancesWriter = new BufferedWriter(
					new FileWriter(Globals.PERFORMANCE_FILE));
			performancesWriter.write(
					"Sample; LockDetectionTime; TextDetectionTime; EncryptionDetectionTime; UnpackingTime; SmaliClassCount; SmaliSize; ApkSize");
			performancesWriter.newLine();
		}

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
		fileEnumeratingThread.setName("FileEnumerationThread");

		unpackingThread = new Thread(new Runnable() {
			@Override
			public void run() {
				unpackingRoutine();
			}
		});
		unpackingThread.setName("UnpackingThread");

		analysisThread = new Thread(new Runnable() {

			private int analyzed = 0;

			@Override
			public void run() {
				System.out.println(String.format("Analyzed %d files out of %d",
						analyzed,
						availableFiles.size()));
				analysisRoutine();
			}
		});
		analysisThread.setName("AnalysisThread");

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

	private static void print(String message) {
		if (!silentMode)
			System.out.print(message);
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

			while ((line = reader.readLine()) != null) {
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

		if (file.isFile() && file.getName().toLowerCase().endsWith(".apk")) {
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
					println("Stalled " + analysisStalls
							+ " times. Maybe analysis thread crahsed? Restarting.");
					restartApplication();
					return;
				}

				try {
					println("Analysis too slow: unpacking routine stalled for "
							+ UNPACKING_WAIT_TIME + " seconds");
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
					unpackingTimes.add((double) (endTime - startTime) / 1000.0);
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
			Integer availableUnpackedDataSize;

			synchronized (availableUnpackedData) {
				availableUnpackedDataSize = availableUnpackedData.size();
			}

			if (availableUnpackedDataSize == 0) {
				synchronized (availableFiles) {
					synchronized (fileEnumerationFinishedLock) {
						if (fileEnumerationFinished
								&& (availableFiles.size() == 0))
							break;
					}
				}

				unpackingStalls++;

				if (unpackingStalls >= MAX_UNPACKING_STALLS) {
					println("Stalled " + analysisStalls
							+ " times. Maybe unpacking thread crahsed? Restarting.");
					restartApplication();
					return;
				}

				try {
					println("Unpacking too slow: analysis routine stalled for "
							+ ANALYSIS_WAIT_TIME + " seconds");
					Thread.sleep(ANALYSIS_WAIT_TIME * 1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				} finally {
					continue;
				}
			} else {
				unpackingStalls = 0;
			}

			applicationData = availableUnpackedData.get(0);
			unpackingTime = unpackingTimes.get(0);

			scanData(applicationData, unpackingTime);

			synchronized (availableUnpackedData) {
				availableUnpackedData.remove(0);
				unpackingTimes.remove(0);
			}
		}
	}

	private static void scanData(final ApplicationData applicationData,
			Double unpackingTime) {
		String apkName = applicationData.getDecodedPackage()
										.getOriginalApk()
										.getAbsolutePath();
		println("Submitted: " + apkName);

		examinedFiles.add(applicationData.getDecodedPackage().getOriginalApk());

		final Wrapper<Boolean> lockDetected = new Wrapper<Boolean>(false);
		final Wrapper<AcceptanceStrategy.Result> textDetected = new Wrapper<AcceptanceStrategy.Result>(
				AcceptanceStrategy.fail());
		final Wrapper<Boolean> encryptionDetected = new Wrapper<Boolean>(false);

		final Wrapper<Double> lockDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);
		final Wrapper<Double> textDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);
		final Wrapper<Double> encryptionDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);

		ExecutorService executor = Executors.newFixedThreadPool(3);

		if (!noTextDetection) {
			executor.submit(new Runnable() {
				@Override
				public void run() {
					Double time = Stopwatch.time(new Runnable() {
						@Override
						public void run() {
							multiResourceScanner.setUnpackedApkDirectory(
									applicationData	.getDecodedPackage()
													.getDecodedDirectory());
							AcceptanceStrategy.Result result = multiResourceScanner.evaluate();

							if (textDetected != null)
								textDetected.value = result;
						}
					});

					if (textDetectionTime != null)
						textDetectionTime.value = time;
				}
			});
		}
		
		if (!noLock)
			executor.submit(new Runnable() {
				@Override
				public void run() {
					Double time = Stopwatch.time(new Runnable() {
						@Override
						public void run() {
							multiLockingStrategy.setTarget(
									applicationData.getDecodedPackage());
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
							encryptionFlowDetector.setTarget(
									applicationData.getDecodedPackage());
							Boolean result = encryptionDetected.value = encryptionFlowDetector.detect();
							if (encryptionDetected != null)
								encryptionDetected.value = result;
						}
					});

					if (encryptionDetectionTime != null)
						encryptionDetectionTime.value = time;
				}
			});

		boolean timedOut = false;
		executor.shutdown();

		try {
			if (!executor.awaitTermination(ANALYSIS_TIMEOUT,
					TimeUnit.SECONDS)) {
				executor.shutdownNow();
				timedOut = true;
			}
		} catch (InterruptedException e) {
		}

		try {
			resultsWriter.write(String.format(
					"%s; %b; %b; %f; %b; \"%s\"; %b; %s\n",
					apkName,
					lockDetected.value,
					textDetected.value.isAccepted(),
					textDetected.value.getScore(),
					encryptionDetected.value,
					textDetected.value.getComment(),
					timedOut,
					textDetected.value.getFileClassification()));

			performancesWriter.write(
					String.format("%s; %f; %f; %f; %f; %d; %d; %d\n",
							apkName,
							lockDetectionTime.value,
							textDetectionTime.value,
							encryptionDetectionTime.value,
							unpackingTime,
							applicationData.getSmaliLoader().getClassesCount(),
							applicationData	.getSmaliLoader()
											.getTotalClassesSize(),
							applicationData	.getDecodedPackage()
											.getOriginalApk()
											.length()));

			resultsWriter.flush();
			performancesWriter.flush();
		} catch (IOException e) {
		}

		// No longer deleting temp files

		if (!timedOut)
			println("Completed: " + apkName);
		else {
			print("Timeout");

			if (textDetectionTime.value == ANALYSIS_TIMEOUT)
				print(" TextDetection");
			if (!noLock && (lockDetectionTime.value == ANALYSIS_TIMEOUT))
				print(" LockDetection");
			if (!noEncryption
					&& (encryptionDetectionTime.value == ANALYSIS_TIMEOUT))
				print(" EncryptionDetection");

			println(": " + apkName);
		}
	}

	private static void closeWriters() throws IOException {
		resultsWriter.close();
		performancesWriter.close();
		examinedFiles.dispose();
	}

	public static void restartApplication() {
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
			String javaBin = System.getProperty("java.home") + File.separator
					+ "bin" + File.separator + "java";
			File currentJar = new File(
					Main.class	.getProtectionDomain()
								.getCodeSource()
								.getLocation()
								.toURI());
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

	// Maximum allowed number of unpacked applications that can reside as an
	// ApplicationData class in memory
	// When this number is reached, the unpacking thread waits for
	// UNPACKING_WAIT_TIME before continuing
	private static final int MAX_ALLOWED_UNPACKED_APKS_IN_MEMORY = 15;
	private static final int UNPACKING_WAIT_TIME = 10; // seconds
	private static final int ANALYSIS_WAIT_TIME = 10;

	private static final int ANALYSIS_TIMEOUT = 30; // seconds

	// Maximum number of times analysis can stall: beyond this, the program
	// assumes the analysis thread has
	// crashed and restarts
	private static final int MAX_ANALYSIS_STALLS = 30;
	private static final int MAX_UNPACKING_STALLS = 30;
	private static int analysisStalls = 0;
	private static int unpackingStalls = 0;

	private static Object fileEnumerationFinishedLock = new Object();
	private static Boolean fileEnumerationFinished = false;
	private static Boolean aborted = false;

	private static Boolean silentMode = false;
	private static Boolean noLock = false;
	private static Boolean noEncryption = false;
	private static Boolean noTextDetection = false;

	private static PersistentFileList examinedFiles;
	private static BufferedWriter resultsWriter;
	private static BufferedWriter performancesWriter;

	private static MultiLockingStrategy multiLockingStrategy;
	private static MultiResourceScanner multiResourceScanner;
	private static EncryptionFlowDetector encryptionFlowDetector;

	private static List<File> availableFiles;
	private static List<ApplicationData> availableUnpackedData;
	private static List<Double> unpackingTimes; // list of times required to
												// unpack an apk

	private static Thread fileEnumeratingThread, unpackingThread,
			analysisThread;
	private static String[] mainArgs;
}
