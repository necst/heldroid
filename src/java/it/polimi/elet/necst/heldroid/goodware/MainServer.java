package it.polimi.elet.necst.heldroid.goodware;

import com.sun.net.httpserver.*;
import it.polimi.elet.necst.heldroid.goodware.features.*;
import it.polimi.elet.necst.heldroid.goodware.features.core.Feature;
import it.polimi.elet.necst.heldroid.goodware.features.core.MetaFeatureGatherer;
import it.polimi.elet.necst.heldroid.pipeline.ApplicationData;
import it.polimi.elet.necst.heldroid.utils.*;
import it.polimi.elet.necst.heldroid.goodware.weka.ApkClassifier;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.*;
import java.util.concurrent.Executors;

public class MainServer implements Runnable {
    private static final int MAX_THREADS_COUNT = 20;

    private ApkClassifier sharedClassifier;
    private File uploadDirectory;
    private File hashDirectory;

    private String[] classLabels;

    public MainServer(ApkClassifier sharedClassifier, File uploadDirectory) {
        this.sharedClassifier = sharedClassifier;
        this.uploadDirectory = uploadDirectory;

        if (!uploadDirectory.exists())
            if (!uploadDirectory.mkdir())
                throw new RuntimeException("Cannot create upload directory!");

        this.hashDirectory = new File(uploadDirectory, "hash");

        if (!hashDirectory.exists())
            if (!hashDirectory.mkdir())
                throw new RuntimeException("Cannot create hash directory!");

        this.classLabels = sharedClassifier.getClassLabels();
    }

    private String fetchResponseByHash(String hash) throws IOException {
        File savedResponse = new File(this.hashDirectory, hash + ".json");

        if (savedResponse.exists())
            return FileSystem.readFileAsString(savedResponse);

        return null;
    }

    private void saveResponseByHash(String hash, String response) throws IOException {
        File savedResponse = new File(this.hashDirectory, hash + ".json");
        OutputStream stream = new FileOutputStream(savedResponse);

        stream.write(response.getBytes());
        stream.close();
    }

    @Override
    public void run() {
        HttpServer server = null;

        try {
            server = HttpServer.create(new InetSocketAddress(8000), 0);
        } catch (IOException e) {
            e.printStackTrace();
        }

        server.createContext("/scan", new ScanHandler());

        HttpContext context = server.createContext("/fetch-scan", new HashHandler());
        context.getFilters().add(new ParameterFilter());

        server.setExecutor(Executors.newFixedThreadPool(MAX_THREADS_COUNT)); // creates a default executor
        server.start();
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
        double[] classDistribution;

        synchronized (MainServer.this.sharedClassifier) {
            classDistribution = MainServer.this.sharedClassifier.computeDistribution(features);
        }

        return this.buildResponseFromResults(features, classDistribution);
    }

    private String buildResponseFromResults(Collection<Feature> features, double[] classDistribution) {
        StringBuilder builder = new StringBuilder();
        boolean firstLine;

        builder.append("{\n");
        builder.append("   features: [\n      ");

        firstLine = true;
        for (Feature f : features) {
            if (!firstLine) builder.append(",\n      ");

            builder.append(String.format("{ name: \"%s\", value: \"%s\" }", f.getName(), f.getValue()));
            firstLine = false;
        }
        builder.append("\n   ],\n   ");

        firstLine = true;
        for (int i = 0; i < classDistribution.length; i++) {
            if (!firstLine) builder.append(",\n   ");

            builder.append(String.format("%s: %s", MainServer.this.classLabels[i], String.valueOf(classDistribution[i])));
            firstLine = false;
        }

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
        metaFeatureGatherer.enableFeatures(MainServer.this.sharedClassifier.getAttributesNames());

        return metaFeatureGatherer;
    }


    private abstract class BaseHandler implements HttpHandler {
        protected void respond(HttpExchange exchange, int statusCode, String message) throws IOException {
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
         * Scans an apk sent as application/octect-stream and returns the scan results.
         * Notice that a connection-reset socket exception is thrown is this method returns without reading the
         * whole request stream. Therefore, to mitigate useless reads, if an error arises before starting the read
         * phase, the client cannot know which error it was.
         * @param t
         * @throws IOException
         */
        public void handle(HttpExchange t) throws IOException {
            File requestFile = this.saveRequestFile(t);
            String hash = FileSystem.hashOf(requestFile);
            String response = MainServer.this.fetchResponseByHash(hash);

            if (response == null) {
                response = MainServer.this.buildResponseFromScan(requestFile);
                MainServer.this.saveResponseByHash(hash, response);
            }

            this.respond(t, 200, response);
        }

        private File saveRequestFile(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            if (!method.equals("POST"))
                throw new RuntimeException("Invalid method: POST required!");

            String boundary = this.getBoundary(exchange);

            if (boundary == null)
                throw new RuntimeException("No boundary specification!");

            int contentLength = Integer.valueOf(exchange.getRequestHeaders().getFirst("Content-Length"));

            String startBoundary = BOUNDARY_PREFIX + boundary;
            String endBoundary = "\r\n" + BOUNDARY_PREFIX + boundary + BOUNDARY_SUFFIX;

            MixedInputStream requestStream = new MixedInputStream(exchange.getRequestBody());
            String line;

            // Reads until a start boundary is found
            while (!requestStream.readLine().equals(startBoundary))
                ;

            // Then keeps reading until a Content-Type header is found. Usually there are two headers at the start
            // of a boundary (Content-Disposition and Content-Type). We assume that only one file is included within
            // the request and thus it is useless to parse Content-Disposition
            while (!(line = requestStream.readLine()).startsWith(CONTENT_TYPE_HEADER))
                ;

            // Gets the mime type of this part
            String mimeType = line.split(":")[1].trim();

            // If it is not an octect stream, fails
            if (!mimeType.equals(OCTET_STREAM_MIME_TYPE))
                throw new RuntimeException("Invalid MIME type: expected application/octet-stream!");

            // Creates a temporary file with prefix upload-, random name, apk suffix, in the given directory
            File resultFile = File.createTempFile("upload-", ".apk", MainServer.this.uploadDirectory);
            OutputStream outputStream = new FileOutputStream(resultFile);

            byte[] buffer = new byte[4096];
            // Index of one of the last blocks of data (not important that is exactly the last)
            int endingBlockIndex = Math.max(0, (contentLength / buffer.length) - 1);
            int readBlocks = 0;
            int brc = 0;

            // There are some empty lines after Content-Type
            requestStream.skipEmptyLines();

            // If more parts are included, only the first is considered (until a startBoundary). If this is the only
            // part, anyway the endBoundary has startBoundary as prefix
            while ((brc = requestStream.read(buffer)) > 0) {
                readBlocks++;

                // Looks for the endBoundary string, but only if we are approaching the end of the octet stream
                // While normally it wouldn't be needed, ApkDecoder complains about unaligned zip files
                if (readBlocks >= endingBlockIndex) {
                    int boundaryIndex = this.findBinaryString(buffer, endBoundary);
                    if (boundaryIndex >= 0) {
                        byte[] tempBuffer = new byte[boundaryIndex];
                        System.arraycopy(buffer, 0, tempBuffer, 0, boundaryIndex);
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

            String mimeType = parts[0].trim().toLowerCase();

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

    private class HashHandler extends BaseHandler implements HttpHandler {
        private static final String SAMPLES_API_KEY = "11d75ea7912546ea97d9fea1d0317b38";

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<?, ?> params = (Map<?, ?>)exchange.getAttribute("parameters");
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
            String command = String.format("python %s/samples_cli.py -log-level DEBUG get -at-key %s %s", MainServer.this.uploadDirectory.getAbsolutePath(), SAMPLES_API_KEY, hash);
            Process downloader = Runtime.getRuntime().exec(command);

            System.out.println("Executed: " + command);

            try {
                downloader.waitFor();
            } catch (InterruptedException e) { }

            File resultFile = new File(MainServer.this.uploadDirectory, hash + ".apk");
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
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            parseGetParameters(exchange);
            chain.doFilter(exchange);
        }

        private void parseGetParameters(HttpExchange exchange) throws UnsupportedEncodingException {
            Map<String, String> parameters = new HashMap<String, String>();
            URI requestedUri = exchange.getRequestURI();
            String query = requestedUri.getRawQuery();

            parseQuery(query, parameters);
            exchange.setAttribute("parameters", parameters);
        }

        @SuppressWarnings("unchecked")
        private void parseQuery(String query, Map<String, String> parameters) throws UnsupportedEncodingException {
            if (query == null)
                return;

            String pairs[] = query.split("[&]");

            for (String pair : pairs) {
                String param[] = pair.split("[=]");

                String key = null;
                String value = null;

                if (param.length > 0)
                    key = URLDecoder.decode(param[0], System.getProperty("file.encoding"));

                if (param.length > 1)
                    value = URLDecoder.decode(param[1], System.getProperty("file.encoding"));

                parameters.put(key, value);
            }
        }
    }
}
