package it.polimi.elet.necst.heldroid.ransomware.emulation;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.HtmlScanner;

public class TrafficScanner {
    private static final String HTML_MIME_TYPE = "text/html";
    private static final String TRACEDROID_USERAGENT = "Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; generic Build/GRJ22) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1";
    private static final File TEMP_HTML_STORAGE = new File("pcap-html");

    private Set<String> unreachableHosts;

    private HtmlScanner htmlScanner;
    private Pcap pcap;
    private StringBuilder errorBuffer;
    private PcapPacketHandler<String> packetHandler;

    private AcceptanceStrategy.Result finalResult;
    private boolean analysisFinished = false;

    public TrafficScanner(final HtmlScanner htmlScanner) {
        if (!TEMP_HTML_STORAGE.exists())
            TEMP_HTML_STORAGE.mkdir();

        this.htmlScanner = htmlScanner;
        this.unreachableHosts = new HashSet<String>();

        this.packetHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                if (analysisFinished)
                    return;

                Tcp tcp = new Tcp();
                Http http = new Http();

                if (!packet.hasHeader(tcp) || !packet.hasHeader(http))
                    return;

                if (!http.hasField(Http.Request.Accept) || !http.fieldValue(Http.Request.Accept).contains(HTML_MIME_TYPE))
                    return;

                File htmlFile = resendRequest(http);

                if (htmlFile == null)
                    return;

                AcceptanceStrategy.Result result = htmlScanner.evaluate(htmlFile);

                if (result.isAccepted()) {
                    analysisFinished = true;
                    finalResult = result;
                }
            }
        };
    }

    public void setPcap(File pcapFile) {
        if (!pcapFile.getAbsolutePath().endsWith(".pcap"))
            throw new IllegalArgumentException("Not a pcap file!");

        this.errorBuffer = new StringBuilder();
        this.pcap = Pcap.openOffline(pcapFile.getAbsolutePath(), errorBuffer);
    }

    public AcceptanceStrategy.Result analyze() {
        if (pcap == null)
            throw new NullPointerException("No pcap file set!");

        finalResult = AcceptanceStrategy.fail();
        analysisFinished = false;

        try {
            pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "");
        } finally {
            pcap.close();
        }

        return finalResult;
    }

    private File resendRequest(Http http) {
        String host = http.fieldValue(Http.Request.Host);
        String requestUrl = "http://" + host + http.fieldValue(Http.Request.RequestUrl);

        if (unreachableHosts.contains(host) || requestUrl.endsWith(".jpg") || requestUrl.endsWith(".png"))
            return null;

        String referer =  http.fieldValue(Http.Request.Referer);
        String language = http.fieldValue(Http.Request.Accept_Language);
        String acceptEncoding = http.fieldValue(Http.Request.Accept_Encoding);
        String accept = http.fieldValue(Http.Request.Accept);

        try {
            URL url = new URL(requestUrl);
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Host", host);
            connection.setRequestProperty("User-Agent", TRACEDROID_USERAGENT);

            if (isNotEmpty(referer))
                connection.setRequestProperty("Referer", referer);

            if (isNotEmpty(language))
                connection.setRequestProperty("Accept-Language", language);

            if (isNotEmpty(acceptEncoding))
                connection.setRequestProperty("Accept-Encoding", acceptEncoding);

            if (isNotEmpty(accept))
                connection.setRequestProperty("Accept", accept);

            connection.setUseCaches(false);

            InputStream is = connection.getInputStream();
            String type = connection.getContentType();
            String encoding = connection.getContentEncoding();
            File htmlFile = new File(TEMP_HTML_STORAGE, String.format("%x.html", http.hashCode()));

            if ((type == null) || (!type.contains("html")))
                return null;

            if (encoding == null)
                encoding = "text/html";

            if (encoding.contains("gzip"))
                decompressGzip(is, htmlFile);
            else
                writeAll(is, htmlFile);

            return htmlFile;
        } catch (Exception e) {
            if (e.getMessage().contains("timed out"))
                unreachableHosts.add(host);
            return null;
        }
    }

    private static boolean decompressGzip(InputStream in, File output) {
        byte[] buffer = new byte[4096];

        try {
            GZIPInputStream gzip = new GZIPInputStream(in);
            FileOutputStream out = new FileOutputStream(output);

            int len;
            while ((len = gzip.read(buffer)) > 0)
                out.write(buffer, 0, len);

            gzip.close();
            out.close();

            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    private static void writeAll(final InputStream in, final File output) throws FileNotFoundException {
        ExecutorService executor = Executors.newSingleThreadExecutor();

        final FileOutputStream out = new FileOutputStream(output);

        executor.submit(new Runnable() {
            @Override
            public void run() {
                byte[] buffer = new byte[4096];

                try {
                    int len;

                    while ((len = in.read(buffer)) > 0) {
                        synchronized (out) {
                            out.write(buffer, 0, len);
                        }
                    }

                    in.close();

                    synchronized (out) {
                        out.close();
                    }
                } catch (IOException ex) { }
            }
        });

        executor.shutdownNow();

        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                synchronized (out) {
                    out.flush();
                    out.close();
                }
            }
        } catch (Exception e) {  }
    }

    private static boolean isNotEmpty(String str) {
        return (str != null) && !str.equals("");
    }
}
