package it.polimi.elet.necst.heldroid.ransomware;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

import javax.xml.parsers.ParserConfigurationException;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminDetector;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult.Policy;
import it.polimi.elet.necst.heldroid.ransomware.emulation.TrafficScanner;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionResult;
import it.polimi.elet.necst.heldroid.ransomware.images.ImageScanner;
import it.polimi.elet.necst.heldroid.ransomware.locking.MultiLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.MultiResourceScanner;
import it.polimi.elet.necst.heldroid.utils.CollectionToJsonConverter;
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import it.polimi.elet.necst.heldroid.utils.MixedInputStream;

import soot.jimple.infoflow.results.InfoflowResults;

public class MainServer implements Runnable {
	private static final int MAX_THREADS_COUNT = 20;

	private Object workersLock = new Object();
	private MultiLockingStrategy multiLockingStrategy;
	private MultiResourceScanner multiResourceScanner;
	private ImageScanner imageScanner;
	private EncryptionFlowDetector encryptionFlowDetector;
	private DeviceAdminDetector deviceAdminDetector;

	private TrafficScanner trafficScanner;

	private File uploadDirectory;
	private File hashDirectory;

	public static void main(String[] args)
    throws ParserConfigurationException {

		File target = new File(args[1]);
		MainServer server = new MainServer(target);
		server.run();
	}

	public MainServer(File uploadDirectory)
			throws ParserConfigurationException {
		this.uploadDirectory = uploadDirectory;

		if (!uploadDirectory.exists())
			if (!uploadDirectory.mkdir())
				throw new RuntimeException("Cannot create upload directory!");

		this.hashDirectory = new File(uploadDirectory, "hash");

		if (!hashDirectory.exists())
			if (!hashDirectory.mkdir())
				throw new RuntimeException("Cannot create hash directory!");

		File samplesCliScript = new File(uploadDirectory, "samples_cli.py");

		if (!samplesCliScript.exists())
			throw new RuntimeException("samples_cli.py not found in "
					+ uploadDirectory.getAbsolutePath());

		this.multiLockingStrategy = Factory.createLockingStrategy();
		this.multiResourceScanner = Factory.createResourceScanner();
		this.imageScanner = Factory.createImageScanner();
		this.encryptionFlowDetector = Factory.createEncryptionFlowDetector();
		this.deviceAdminDetector = Factory.createDeviceAdminDetector();
		this.trafficScanner = Factory.createTrafficScanner();
	}

	private String fetchResponseByHash(String hash) throws IOException {
		File savedResponse = new File(this.hashDirectory, hash + ".json");

		if (savedResponse.exists())
			return FileSystem.readFileAsString(savedResponse);

		return null;
	}

	private void saveResponseByHash(String hash, String response)
			throws IOException {
		File savedResponse = new File(this.hashDirectory, hash + ".json");
		OutputStream stream = new FileOutputStream(savedResponse);

		stream.write(response.getBytes());
		stream.close();
	}

	@Override
	public void run() {
		HttpServer server = null;

		try {
			server = HttpServer.create(new InetSocketAddress(8001), 0);
		} catch (IOException e) {
			e.printStackTrace();
		}

		server.createContext("/scan", new ScanHandler());
		server.createContext("/pcap-scan", new PcapScanHandler());

		HttpContext context = server.createContext("/fetch-scan",
				new HashHandler());
		context	.getFilters()
				.add(new ParameterFilter());

		context = server.createContext("/fetch-apk", new ApkHandler());
		context	.getFilters()
				.add(new ParameterFilter());

		// Handle APK downloads

		server.setExecutor(Executors.newFixedThreadPool(MAX_THREADS_COUNT)); // creates
																				// a
																				// default
																				// executor
		server.start();
	}

	private String buildResponseFromScan(File file) {
		ApplicationData applicationData;

		try {
			applicationData = ApplicationData.open(file);
		} catch (Exception e) {
			return "Error unpacking: " + e.getMessage();
		}

		boolean lockDetected, encryptionDetected, deviceAdminUsed;
		List<Policy> policies;
		Set<String> languages;
		AcceptanceStrategy.Result textResult;
		EncryptionResult encryptionResult;

		synchronized (workersLock) {
			multiLockingStrategy.setTarget(applicationData.getDecodedPackage());
			multiResourceScanner.setUnpackedApkDirectory(
					applicationData	.getDecodedPackage()
									.getDecodedDirectory());
			encryptionFlowDetector.setTarget(
					applicationData.getDecodedPackage());

			lockDetected = multiLockingStrategy.detect();
			// encryptionDetected = encryptionFlowDetector.detect();
			encryptionResult = encryptionFlowDetector.detect().value;
			InfoflowResults infoFlowResults = encryptionResult.getInfoFlowResults();
			encryptionDetected = (infoFlowResults != null
					&& infoFlowResults	.getResults()
										.size() > 0);
			DeviceAdminResult deviceAdminResult = deviceAdminDetector.detect(true).value;
			deviceAdminUsed = deviceAdminResult.isDeviceAdminUsed();
			policies = deviceAdminResult.getPolicies();

			AcceptanceStrategy.Result textScannerResult = multiResourceScanner.evaluate();
			AcceptanceStrategy.Result imageScannerResult = null;

			boolean resultFromImages = false;
			/*
			 * Analyze images only if no text is found yet
			 */
			if (!textScannerResult.isAccepted()) {
				if (imageScanner == null) {
					imageScanner = Factory.createImageScanner();
				}
				imageScanner.setUnpackedApkDirectory(
						applicationData	.getDecodedPackage()
										.getDecodedDirectory());
				imageScanner.setTesseractLanguage(
						multiResourceScanner.getEncounteredLanguagesRaw());
				imageScannerResult = imageScanner.evaluate();
			}
			
			if (imageScannerResult != null) {
				resultFromImages = imageScannerResult.getScore() > textScannerResult.getScore();
			}

			if (resultFromImages) {
				textResult = imageScannerResult;
				languages = imageScanner.getEncounteredLanguages();
			} else {
				textResult = textScannerResult;
				languages = multiResourceScanner.getEncounteredLanguages();
			}
		}

		applicationData.dispose();

		return MainServer.buildResponseFromResults(lockDetected,
				encryptionResult.isWritable(),
				encryptionDetected,
				deviceAdminUsed,
				policies,
				textResult,
				languages);
	}

	private static String buildResponseFromResults(boolean lockDetected,
			boolean hasRWPermission, boolean encryptionDetected,
			boolean deviceAdminUsed, List<Policy> policies,
			AcceptanceStrategy.Result textResult, Set<String> languages) {
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
		builder.append(String.format("   \"textDetected\": %b,\n",
				textResult.isAccepted()));
		builder.append(String.format("   \"textScore\": %s,\n",
				formatter.format(textResult.getScore())));
		builder.append(String.format("   \"languages\": %s,\n", CollectionToJsonConverter.convert(languages)));
		builder.append(String.format("   \"hasRWPermission\": %b,\n",
				hasRWPermission));
		builder.append(String.format("   \"encryptionDetected\": %b,\n",
				encryptionDetected));
		builder.append(String.format("   \"deviceAdminUsed\": %b,\n",
				deviceAdminUsed));
		builder.append(String.format("   \"deviceAdminPolicies\": \"%s\",\n",
				policies));
		builder.append(String.format("   \"textComment\": \"%s\",\n",
				textResult.getComment()));
		builder.append(String.format("   \"suspiciousFiles\": \"%s\"\n",
				textResult.getFileClassification()));
		builder.append("}");

		return builder.toString();
	}

	private String buildResponseFromPcapScan(File file) {
		AcceptanceStrategy.Result textResult;

		synchronized (trafficScanner) {
			trafficScanner.setPcap(file);
			textResult = trafficScanner.analyze();
		}

		StringBuilder builder = new StringBuilder();

		builder.append("{\n");
		builder.append(String.format("   textDetected: %b,\n",
				textResult.isAccepted()));
		builder.append(
				String.format("   textScore: %f,\n", textResult.getScore()));
		builder.append(String.format("   textComment: \"%s\"\n",
				textResult.getComment()));
		builder.append("}");

		return builder.toString();
	}

	private abstract class BaseHandler implements HttpHandler {
		protected void respond(HttpExchange exchange, int statusCode,
				String message) throws IOException {
			byte[] bytes = message.getBytes();

			exchange.sendResponseHeaders(501, bytes.length);

			OutputStream stream = exchange.getResponseBody();
			stream.write(bytes);
			stream.close();
		}
	}

	private class ScanHandler extends BaseHandler implements HttpHandler {
		private static final String MULTIPLART_MIME_TYPE = "multipart/form-data";
		private static final String OCTET_STREAM_MIME_TYPE = "application/octet-stream";
		private static final String CONTENT_TYPE_HEADER = "Content-Type";
		private static final String BOUNDARY_FIELD = "boundary";
		private static final String BOUNDARY_PREFIX = "--";
		private static final String BOUNDARY_SUFFIX = "--";

		/**
		 * Scans an apk sent as application/octect-stream and returns the scan
		 * results. Notice that a connection-reset socket exception is thrown is
		 * this method returns without reading the whole request stream.
		 * Therefore, to mitigate useless reads, if an error arises before
		 * starting the read phase, the client cannot know which error it was.
		 * 
		 * @param t
		 * @throws IOException
		 */
		public void handle(HttpExchange t) throws IOException {
			File requestFile = File.createTempFile("upload-",
					".apk",
					MainServer.this.uploadDirectory);
			this.saveRequestFile(t, requestFile);

			String hash = FileSystem.hashOf(requestFile);
			String response = MainServer.this.fetchResponseByHash(hash);

			if (response == null) {
				response = MainServer.this.buildResponseFromScan(requestFile);
				MainServer.this.saveResponseByHash(hash, response);
			}

			this.respond(t, 200, response);
		}

		protected File saveRequestFile(HttpExchange exchange, File resultFile)
				throws IOException {
			String method = exchange.getRequestMethod();

			if (!method.equals("POST"))
				throw new RuntimeException("Invalid method: POST required!");

			String boundary = this.getBoundary(exchange);

			if (boundary == null)
				throw new RuntimeException("No boundary specification!");

			int contentLength = Integer.valueOf(exchange.getRequestHeaders()
														.getFirst(
																"Content-Length"));

			String startBoundary = BOUNDARY_PREFIX + boundary;
			String endBoundary = "\r\n" + BOUNDARY_PREFIX + boundary
					+ BOUNDARY_SUFFIX;

			MixedInputStream requestStream = new MixedInputStream(
					exchange.getRequestBody());
			String line;

			// Reads until a start boundary is found
			while (!requestStream	.readLine()
									.equals(startBoundary))
				;

			// Then keeps reading until a Content-Type header is found. Usually
			// there are two headers at the start
			// of a boundary (Content-Disposition and Content-Type). We assume
			// that only one file is included within
			// the request and thus it is useless to parse Content-Disposition
			while (!(line = requestStream.readLine()).startsWith(
					CONTENT_TYPE_HEADER))
				;

			// Gets the mime type of this part
			String mimeType = line.split(":")[1].trim();

			// If it is not an octect stream, fails
			if (!mimeType.equals(OCTET_STREAM_MIME_TYPE)) {
				requestStream.close();
				throw new RuntimeException(
						"Invalid MIME type: expected application/octet-stream!");
			}

			OutputStream outputStream = new FileOutputStream(resultFile);

			byte[] buffer = new byte[4096];
			// Index of one of the last blocks of data (not important that is
			// exactly the last)
			int endingBlockIndex = Math.max(0,
					(contentLength / buffer.length) - 1);
			int readBlocks = 0;
			int brc = 0;

			// There are some empty lines after Content-Type
			requestStream.skipEmptyLines();

			// If more parts are included, only the first is considered (until a
			// startBoundary). If this is the only
			// part, anyway the endBoundary has startBoundary as prefix
			while ((brc = requestStream.read(buffer)) > 0) {
				readBlocks++;

				// Looks for the endBoundary string, but only if we are
				// approaching the end of the octet stream
				// While normally it wouldn't be needed, ApkDecoder complains
				// about unaligned zip files
				if (readBlocks >= endingBlockIndex) {
					int boundaryIndex = this.findBinaryString(buffer,
							endBoundary);
					if (boundaryIndex >= 0) {
						byte[] tempBuffer = new byte[boundaryIndex];
						System.arraycopy(buffer,
								0,
								tempBuffer,
								0,
								boundaryIndex);
						buffer = tempBuffer;
						brc = buffer.length;
					}
				}

				outputStream.write(buffer, 0, brc);
			}

			requestStream.close();
			outputStream.close();

			return resultFile;
		}

		private int findBinaryString(byte[] buffer, String target) {
			byte[] targetBytes = target.getBytes();

			if (buffer.length < targetBytes.length)
				return -1;

			for (int i = 0; i < buffer.length - targetBytes.length; i++) {
				boolean found = true;

				for (int j = 0; j < targetBytes.length; j++)
					if (buffer[j + i] != targetBytes[j]) {
						found = false;
						break;
					}

				if (found)
					return i;
			}

			return -1;
		}

		private String getBoundary(HttpExchange exchange) {
			Headers headers = exchange.getRequestHeaders();
			String contentType = headers.getFirst(CONTENT_TYPE_HEADER);
			String[] parts = contentType.split(";");

			String mimeType = parts[0]	.trim()
										.toLowerCase();

			if (!mimeType.equals(MULTIPLART_MIME_TYPE))
				return null;

			for (int i = 1; i < parts.length; i++) {
				String part = parts[i].trim();

				if (part.startsWith(BOUNDARY_FIELD)) {
					String[] boundarySpecs = part.split("=");
					return boundarySpecs[1].trim();
				}
			}

			return null;
		}
	}

	private class PcapScanHandler extends ScanHandler implements HttpHandler {
		@Override
		public void handle(HttpExchange t) throws IOException {
			File requestFile = File.createTempFile("upload-",
					".pcap",
					MainServer.this.uploadDirectory);
			this.saveRequestFile(t, requestFile);

			String hash = FileSystem.hashOf(requestFile) + ".pcap";
			String response = MainServer.this.fetchResponseByHash(hash);

			if (response == null) {
				response = MainServer.this.buildResponseFromPcapScan(
						requestFile);
				MainServer.this.saveResponseByHash(hash, response);
			}

			this.respond(t, 200, response);
		}
	}

	private class ApkHandler extends BaseHandler implements HttpHandler {

		private final File baseFolder;

		public ApkHandler() {
			baseFolder = new File("/home/andronio/experiments/Automator");
		}

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			Map<?, ?> params = (Map<?, ?>) exchange.getAttribute("parameters");

			String family = (String) params.get("family");
			String hash = (String) params.get("hash");

			if (family == null || hash == null) {
				respond(exchange, 400, "No hash or family provided");
				return;
			}

			File familyFolder = new File(baseFolder, family).getCanonicalFile();

			if (!familyFolder.exists()) {
				respond(exchange, 404, "Family not found");
			}

			if (!familyFolder	.getParentFile()
								.equals(baseFolder.getCanonicalFile())) {
				respond(exchange, 400, "Bad family");
				return;
			}

			File apk = new File(familyFolder, hash + ".apk").getCanonicalFile();

			if (!apk.getParentFile()
					.equals(familyFolder.getCanonicalFile())) {
				respond(exchange, 400, "Bad file");
				return;
			}

			if (!apk.exists()) {
				respond(exchange, 404, "Apk not found");
				return;
			}

			// Set output file name
			Headers responseHeaders = exchange.getResponseHeaders();
			responseHeaders.add("Content-Disposition",
					"attachment; filename=\"" + hash + ".apk\"");

			// Start sending file
			exchange.sendResponseHeaders(200, apk.length());
			OutputStream os = exchange.getResponseBody();
			FileInputStream fis = new FileInputStream(apk);

			byte[] buffer = new byte[8 * 1024]; // 8KB buffer
			int read = 0;
			while ((read = fis.read(buffer)) > -1) {
				os.write(buffer, 0, read);
			}

			fis.close();
			os.close();
		}
	}

	private class HashHandler extends BaseHandler implements HttpHandler {
		private static final String SAMPLES_API_KEY = "11d75ea7912546ea97d9fea1d0317b38";

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			Map<?, ?> params = (Map<?, ?>) exchange.getAttribute("parameters");
			String hash = (String) params.get("hash");
			String response = MainServer.this.fetchResponseByHash(hash);

			if (response == null) {
				File sample = this.fetchSample(hash);

				if (!sample.exists()) {
					this.respond(exchange, 404, "Not found");
					return;
				}

				response = MainServer.this.buildResponseFromScan(sample);
				MainServer.this.saveResponseByHash(hash, response);
			}

			this.respond(exchange, 200, response);
		}

		private File fetchSample(String hash) throws IOException {
			String command = String.format(
					"python %s/samples_cli.py -log-level DEBUG get -at-key %s %s",
					MainServer.this.uploadDirectory.getAbsolutePath(),
					SAMPLES_API_KEY,
					hash);
			Process downloader = Runtime.getRuntime()
										.exec(command);

			System.out.println("Executed: " + command);

			try {
				downloader.waitFor();
			} catch (InterruptedException e) {
			}

			File resultFile = new File(MainServer.this.uploadDirectory,
					hash + ".apk");
			File misplacedFile = new File(hash + ".apk");

			if (misplacedFile.exists())
				misplacedFile.renameTo(resultFile);

			return resultFile;
		}
	}

	public class ParameterFilter extends Filter {
		@Override
		public String description() {
			return "Parses the requested URI for parameters";
		}

		@Override
		public void doFilter(HttpExchange exchange, Chain chain)
				throws IOException {
			parseGetParameters(exchange);
			chain.doFilter(exchange);
		}

		private void parseGetParameters(HttpExchange exchange)
				throws UnsupportedEncodingException {
			Map<String, String> parameters = new HashMap<String, String>();
			URI requestedUri = exchange.getRequestURI();
			String query = requestedUri.getRawQuery();

			parseQuery(query, parameters);
			exchange.setAttribute("parameters", parameters);
		}

		private void parseQuery(String query, Map<String, String> parameters)
				throws UnsupportedEncodingException {
			if (query == null)
				return;

			String pairs[] = query.split("[&]");

			for (String pair : pairs) {
				String param[] = pair.split("[=]");

				String key = null;
				String value = null;

				if (param.length > 0)
					key = URLDecoder.decode(param[0],
							System.getProperty("file.encoding"));

				if (param.length > 1)
					value = URLDecoder.decode(param[1],
							System.getProperty("file.encoding"));

				parameters.put(key, value);
			}
		}
	}
}
