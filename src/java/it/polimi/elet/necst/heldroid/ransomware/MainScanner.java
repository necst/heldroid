package it.polimi.elet.necst.heldroid.ransomware;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminDetector;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult.Policy;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionResult;
import it.polimi.elet.necst.heldroid.ransomware.images.ImageScanner;
import it.polimi.elet.necst.heldroid.ransomware.locking.MultiLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.photo.PhotoAdminResult;
import it.polimi.elet.necst.heldroid.ransomware.photo.PhotoDetector;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.MultiResourceScanner;
import it.polimi.elet.necst.heldroid.utils.CFGUtils;
import it.polimi.elet.necst.heldroid.utils.CollectionToJsonConverter;
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import it.polimi.elet.necst.heldroid.utils.Options;
import it.polimi.elet.necst.heldroid.utils.PersistentFileList;
import it.polimi.elet.necst.heldroid.utils.Stopwatch;
import it.polimi.elet.necst.heldroid.utils.Wrapper;

import soot.jimple.infoflow.cfg.SharedCfg;
import soot.jimple.infoflow.results.InfoflowResults;

public class MainScanner {

	/**
	 * Contains the directory in which the JSON report should be saved
	 */
	private static File jsonDirectory;

  private final static Logger logger = LoggerFactory.getLogger(MainScanner.class); 

	public static void main(String[] args) throws ParserConfigurationException,
			IOException, InterruptedException {
		mainArgs = args;

    logger.info("Starting off!");

		final File target = new File(args[1]);
		final File result = new File(args[2]);
		jsonDirectory = new File(args[3]);

		final Options options = new Options(args);

		silentMode = options.contains("-s");
		noLock = options.contains("-nl");
		noEncryption = options.contains("-ne");
		noTextDetection = options.contains("-nt");
		noDeviceAdminDetection = options.contains("-na");

    logger.info("Instantiating components...");

    logger.info("Creating lock-strategy detector");
		multiLockingStrategy = Factory.createLockingStrategy();

    logger.info("Creaating resource scanner");
		multiResourceScanner = Factory.createResourceScanner();

    logger.info("Creating image scanner");
		imageScanner = Factory.createImageScanner();

    logger.info("Creating encryption-strategy detector");
		encryptionFlowDetector = Factory.createEncryptionFlowDetector();

    logger.info("Creating device-admin detector");
		deviceAdminDetector = Factory.createDeviceAdminDetector();

    logger.info("Creating photo-admin detector");
		photoAdminDetector = Factory.createPhotoAdminDetector();

    logger.info("Components ready to analyze!");

		examinedFiles = new PersistentFileList(
				Globals.EXAMINED_FILES_LIST_FILE);

		if (result.exists())
			resultsWriter = new BufferedWriter(new FileWriter(result, true));
		else {
			resultsWriter = new BufferedWriter(new FileWriter(result));
			resultsWriter.write(
					"Sample; LockDetected; LockStrategy; TextDetected; TextScore; Languages; RW Permission; EncryptionDetected; PhotoCaptureDetected; DeviceAdminUsed; DeviceAdminPolicies; DevAdminFromReflection; Comment; TimedOut; Classified files");
			resultsWriter.newLine();
		}

		if (Globals.PERFORMANCE_FILE.exists())
			performancesWriter = new BufferedWriter(
					new FileWriter(Globals.PERFORMANCE_FILE, true));
		else {
			performancesWriter = new BufferedWriter(
					new FileWriter(Globals.PERFORMANCE_FILE));
			performancesWriter.write(
					"Sample; LockDetectionTime; TextDetectionTime; EncryptionDetectionTime; DeviceAdminDetectionTime; UnpackingTime; SmaliClassCount; SmaliSize; ApkSize");
			performancesWriter.newLine();
		}

		availableFiles = new ArrayList<File>();
		availableUnpackedData = new ArrayList<ApplicationData>();
		unpackingTimes = new ArrayList<Double>();

    logger.info("Preparing workers threads");

		fileEnumeratingThread = new Thread(new Runnable() {
			@Override
			public void run() {
				if (target.isDirectory()) {
					enumerateDirectory(target);
				} else {
					String name = target.getName()
										.toLowerCase();

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
			@Override
			public void run() {
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
			logger.info("Skipped: " + file.getName());
			return;
		}

		if (file.isFile() && file	.getName()
									.toLowerCase()
									.endsWith(".apk")) {
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
					logger.warn("Stalled " + analysisStalls
							+ " times. Maybe analysis thread crahsed? Restarting.");
					restartApplication();
					return;
				}

				try {
					logger.warn("Analysis too slow: unpacking routine stalled for "
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

			logger.info("Unpacking: " + file.getName());

			try {
				Long startTime = System.currentTimeMillis();
				ApplicationData applicationData = ApplicationData.open(file);
				Long endTime = System.currentTimeMillis();

				synchronized (availableUnpackedData) {
					availableUnpackedData.add(applicationData);
					unpackingTimes.add((double) (endTime - startTime) / 1000.0);
				}

				logger.info("Unpacked: " + file.getName());
			} catch (Exception e) {
				logger.warn("Dropped: " + file.getName() + "; " + e.getMessage());
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
					logger.warn("Stalled " + analysisStalls
              + " times. Maybe unpacking thread crahsed? Restarting.");
					restartApplication();
					return;
				}

				try {
					logger.warn("Unpacking too slow: analysis routine stalled for "
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
		logger.info("Submitted: " + apkName);

		examinedFiles.add(applicationData	.getDecodedPackage()
											.getOriginalApk());

		final Wrapper<Boolean> lockDetected = new Wrapper<Boolean>(false);
		final Wrapper<String> lockStrategy = new Wrapper<>(null);
		final Wrapper<AcceptanceStrategy.Result> textDetected = new Wrapper<AcceptanceStrategy.Result>(
				AcceptanceStrategy.fail());
		final Wrapper<Boolean> encryptionDetected = new Wrapper<Boolean>(false);
		final Wrapper<Boolean> photoCaptureDetected = new Wrapper<>(false);
		final Wrapper<Boolean> hasRWPermission = new Wrapper<>(false);
		final Wrapper<Boolean> deviceAdminUsed = new Wrapper<Boolean>(false);
		final Wrapper<Boolean> encryptionDetectorTimedOut = new Wrapper<>(
				false);
		final Wrapper<Set<String>> languages = new Wrapper<Set<String>>(null);
		final Wrapper<Boolean> isFromReflection = new Wrapper<>(false);
		final Wrapper<PhotoAdminResult> photoCaptureResult = new Wrapper<>(null);
		final Wrapper<List<Policy>> deviceAdminPolicies = new Wrapper<List<Policy>>(
				null);
		final Wrapper<Double> lockDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);
		final Wrapper<Double> textDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);
		final Wrapper<Double> encryptionDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);
		final Wrapper<Double> deviceAdminDetectionTime = new Wrapper<Double>(
				(double) ANALYSIS_TIMEOUT);

		ExecutorService executor = Executors.newFixedThreadPool(4);

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
							AcceptanceStrategy.Result textResult = multiResourceScanner.evaluate();
							AcceptanceStrategy.Result imageResult = null;
							boolean resultFromImages = false;
							/*
							 * Analyze images only if no text is found yet
							 */
							if (!textResult.isAccepted()) {
								if (imageScanner == null) {
									imageScanner = Factory.createImageScanner();
								}
								imageScanner.setUnpackedApkDirectory(
										applicationData	.getDecodedPackage()
														.getDecodedDirectory());
								imageScanner.setTesseractLanguage(
										multiResourceScanner.getEncounteredLanguagesRaw());
								imageResult = imageScanner.evaluate();
							}

							/*
							 * If both results are available then take the one
							 * with higher score
							 */
							if (imageResult != null) {
								resultFromImages = imageResult.getScore() > textResult.getScore();
							}

							if (languages != null) {
								if (languages.value == null) {
									languages.value = new HashSet<>();
								}

								// Add languages depending on who did the
								// analysis
								if (resultFromImages) {
									languages.value.addAll(
											imageScanner.getEncounteredLanguages());
								} else {
									languages.value.addAll(
											multiResourceScanner.getEncounteredLanguages());
								}
							}

							if (textDetected != null)
								textDetected.value = resultFromImages
										? imageResult : textResult;
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
							
							if (result) {
								lockStrategy.value = multiLockingStrategy.getSuccessfulStrategy();
							}
							
						}
					});

					if (lockDetectionTime != null)
						lockDetectionTime.value = time;
				}
			});

		if (!noEncryption) {
			executor.submit(new Runnable() {
				@Override
				public void run() {
					Double time = Stopwatch.time(new Runnable() {
						@Override
						public void run() {
							encryptionFlowDetector.setTarget(
									applicationData.getDecodedPackage());
							Wrapper<EncryptionResult> encryptionResult = encryptionFlowDetector.detect();

							if (encryptionResult.value != null) {
								if (encryptionResult.value.isTimedout()) {
									encryptionDetectorTimedOut.value = true;
								} else {
									InfoflowResults infoFlow = encryptionResult.value.getInfoFlowResults();
									boolean result = (infoFlow != null
											&& infoFlow.getResults() != null
											&& infoFlow	.getResults()
														.size() > 0);

									if (encryptionDetected != null)
										encryptionDetected.value = result;
								}
							} else {
								encryptionDetected.value = null;
							}

							if (hasRWPermission != null) {
								hasRWPermission.value = encryptionResult.value.isWritable();
								
								if (!hasRWPermission.value) {
									SharedCfg.setCfg(CFGUtils.createCfg(applicationData.getDecodedPackage()));
								}
							}
						}
					});

					if (encryptionDetectionTime != null)
						encryptionDetectionTime.value = time;
				}
			});
		}

		if (!noDeviceAdminDetection) {
			executor.submit(new Runnable() {

				@Override
				public void run() {
					Double time = Stopwatch.time(new Runnable() {

						@Override
						public void run() {
							deviceAdminDetector.setTarget(
									applicationData.getDecodedPackage());

							photoAdminDetector.setTarget(
									applicationData.getDecodedPackage());

							/*
							 * If the EncryptionFlowDetector is enabled, we will
							 * reuse the CFG that it generates, otherwise we
							 * will generate a new one
							 */
							boolean reuseCfg = !noEncryption;

							Wrapper<DeviceAdminResult> deviceAdminResult = null;
							try {
								deviceAdminResult = deviceAdminDetector.detect(
										reuseCfg);

								photoCaptureResult.value = photoAdminDetector.detect(
										reuseCfg).value;
								
								photoCaptureDetected.value = photoCaptureResult.value.isPhotoDetected();
							} catch (Throwable e) {
								e.printStackTrace();
							}
							if (deviceAdminResult != null) {
								if (deviceAdminResult.value != null) {
									DeviceAdminResult res = deviceAdminResult.value;

									if (deviceAdminPolicies != null)
										deviceAdminPolicies.value = res.getPolicies();

									if (deviceAdminUsed != null)
										deviceAdminUsed.value = true;
									
									isFromReflection.value = deviceAdminResult.value.isFromReflection() || photoCaptureResult.value.isFromReflection();

									// No longer needed
									deviceAdminResult = null;
								}
							}
						}
					});

					if (deviceAdminDetectionTime != null)
						deviceAdminDetectionTime.value = time;
				}
			});
		}

		boolean timedOut = false;
		executor.shutdown();

		try {
			if (!executor.awaitTermination(ANALYSIS_TIMEOUT,
					TimeUnit.SECONDS)) {
				logger.warn("Analysis timed out");
				executor.shutdownNow();
				timedOut = true;
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// Check if encryption analysis timedout
		timedOut = timedOut || encryptionDetectorTimedOut.value;

		// Create JSON
		try {
      String fn = FilenameUtils.getBaseName(apkName);
			File hashDirectory = new File(MainScanner.jsonDirectory,
					fn + ".json");
			OutputStream jsonWriter = new FileOutputStream(hashDirectory);
			String json = MainScanner.buildResponseFromResults(
					lockDetected.value,
					lockStrategy.value,
					hasRWPermission.value,
					encryptionDetected.value,
					photoCaptureDetected.value,
					deviceAdminUsed.value,
					deviceAdminPolicies.value,
					isFromReflection.value,
					textDetected.value,
					languages.value);
			jsonWriter.write(json.getBytes());
			jsonWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			resultsWriter.write(String.format(
					"%s; %b; %s; %b; %f; %s; %b; %b; %b; %b; %s; %s; \"%s\"; %b; %s\n",
					apkName,
					lockDetected.value,
					lockStrategy.value,
					textDetected.value.isAccepted(),
					textDetected.value.getScore(),
					languages.value,
					hasRWPermission.value,
					encryptionDetected.value,
					photoCaptureDetected.value,
					deviceAdminUsed.value,
					deviceAdminPolicies.value,
					isFromReflection.value,
					textDetected.value.getComment(),
					timedOut,
					textDetected.value.getFileClassification()));

			performancesWriter.write(
					String.format("%s; %f; %f; %f; %f; %f; %d; %d; %d\n",
							apkName,
							lockDetectionTime.value,
							textDetectionTime.value,
							encryptionDetectionTime.value,
							deviceAdminDetectionTime.value,
							unpackingTime,
							applicationData	.getSmaliLoader()
											.getClassesCount(),
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
			logger.info("Completed: " + apkName);
		else {
			print("Timeout");

			if (textDetectionTime.value == ANALYSIS_TIMEOUT)
				print(" TextDetection");
			if (!noLock && (lockDetectionTime.value == ANALYSIS_TIMEOUT))
				print(" LockDetection");
			if (!noEncryption
					&& (encryptionDetectionTime.value == ANALYSIS_TIMEOUT))
				print(" EncryptionDetection");

			print(": " + apkName);
		}
	}

	private static String buildResponseFromResults(boolean lockDetected,
			String lockStrategy,
			boolean hasRWPermission, boolean encryptionDetected,
			boolean photoCaptureDetected, boolean deviceAdminUsed,
			List<Policy> policies, boolean isFromReflection, AcceptanceStrategy.Result textResult,
			Set<String> languages) {
		StringBuilder builder = new StringBuilder();

		/*
		 * By default the decimal separator is a comma. This is wrong in JSON,
		 * since it expects a dot, so we need to use a DecimalFormat object.
		 */

		DecimalFormatSymbols symbols = new DecimalFormatSymbols(
				Locale.getDefault());
		symbols.setDecimalSeparator('.');

		DecimalFormat formatter = new DecimalFormat();
		formatter.setDecimalFormatSymbols(symbols);

		builder.append("{\n");
		builder.append(
				String.format("   \"lockDetected\": %b,\n", lockDetected));
		builder.append(
				String.format("   \"lockStrategy\": \"%s\",\n", lockStrategy));
		builder.append(String.format("   \"textDetected\": %b,\n",
				textResult.isAccepted()));
		builder.append(String.format("   \"textScore\": %s,\n",
				formatter.format(textResult.getScore())));
		builder.append(String.format("   \"languages\": %s,\n",
				CollectionToJsonConverter.convert(languages)));
		builder.append(String.format("   \"hasRWPermission\": %b,\n",
				hasRWPermission));
		builder.append(String.format("   \"encryptionDetected\": %b,\n",
				encryptionDetected));
		builder.append(String.format("   \"photoCaptureDetected\": %b,\n",
				photoCaptureDetected));
		builder.append(String.format("   \"deviceAdminUsed\": %b,\n",
				deviceAdminUsed));
		builder.append(String.format("   \"deviceAdminPolicies\": \"%s\",\n",
				policies));
		builder.append(String.format("   \"fromReflection\": %b,\n",
				isFromReflection));
		builder.append(String.format("   \"textComment\": \"%s\",\n",
				textResult.getComment()));
		builder.append(String.format("   \"suspiciousFiles\": \"%s\"\n",
				textResult.getFileClassification()));
		builder.append("}");

		return builder.toString();
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
//			File currentJar = new File(Main.class	.getProtectionDomain()
//													.getCodeSource()
//													.getLocation()
//													.toURI());
			File currentJar = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().getFile());
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
	private static final int UNPACKING_WAIT_TIME = 20; // seconds
	private static final int ANALYSIS_WAIT_TIME = 20;

	private static final int ANALYSIS_TIMEOUT = 210; // seconds

	// Maximum number of times analysis can stall: beyond this, the program
	// assumes the analysis thread has
	// crashed and restarts
	private static final int MAX_ANALYSIS_STALLS = 50;
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
	private static Boolean noDeviceAdminDetection = false;

	private static PersistentFileList examinedFiles;
	private static BufferedWriter resultsWriter;
	private static BufferedWriter performancesWriter;

	private static MultiLockingStrategy multiLockingStrategy;
	private static MultiResourceScanner multiResourceScanner;
	private static ImageScanner imageScanner;
	private static EncryptionFlowDetector encryptionFlowDetector;
	private static DeviceAdminDetector deviceAdminDetector;
	private static PhotoDetector photoAdminDetector;

	private static List<File> availableFiles;
	private static List<ApplicationData> availableUnpackedData;
	private static List<Double> unpackingTimes; // list of times required to
												// unpack an apk

	private static Thread fileEnumeratingThread, unpackingThread,
			analysisThread;
	private static String[] mainArgs;
}
