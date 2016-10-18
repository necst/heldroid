package it.polimi.elet.necst.heldroid.ransomware;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

import javax.xml.parsers.ParserConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cybozu.labs.langdetect.DetectorFactory;
import com.cybozu.labs.langdetect.LangDetectException;

import it.polimi.elet.necst.heldroid.apk.DecodingException;
import it.polimi.elet.necst.heldroid.ransomware.emulation.TrafficScanner;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.AcceptanceStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.HtmlScanner;
import it.polimi.elet.necst.heldroid.utils.Options;

import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.sentdetect.SentenceSample;
import opennlp.tools.sentdetect.SentenceSampleStream;
import opennlp.tools.util.ObjectStream;
import opennlp.tools.util.PlainTextByLineStream;
import opennlp.tools.util.TrainingParameters;

public class Main {
  private final static Logger logger = LoggerFactory.getLogger(Main.class); 

  public static void main(String args[]) throws IOException, ParserConfigurationException, DecodingException,
      LangDetectException, InterruptedException {

    logger.info("Starting off!");

    if (args.length < 1) {
      printUsage();
      return;
    }

    String op = args[0];
    Options options = new Options(args);
    DetectorFactory.loadProfile(Globals.LANGUAGE_PROFILES_DIRECTORY);

    if (op.equals("scan")) {
      logger.info("Scanning mode");

      if (options.contains("-sequential"))
        MainScannerSequential.main(args);
      else
        MainScanner.main(args);

    } else if (op.equals("server"))
      MainServer.main(args);
    else if (op.equals("pcap"))
      pcapAnalysis(args);
    else if (op.equals("learn"))
      learnSentenceDetector(args);
    else
      printUsage();
  }

  private static void printUsage() {
    String jarName = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getName();

    System.out.println("java -jar " + jarName + " (server|scan|pcap|learn) [[args]]\n" + "\n"
        + "    server <conf_dir> <watch_folder>:\n"
        + "       Scan any new APK file popping up in the <watch_folder> and spin up a webserver\n"
        + "       The <conf_dir> must contain:\n" + "         - AndroidCallbacks.txt\n"
        + "         - Conditions.txt\n" + "         - EasyTaintWrapperSource.txt\n"
        + "         - SourcesAndSinks.txt\n" + "\n"
        + "    scan <conf_dir> <directory> <output.csv> <json_result_directory>:\n"
        + "       Scan all *.apk in directory (recursively). Save JSON data in <json_result_directory>.\n"
        + "       The <conf_dir> must contain:\n" + "         - AndroidCallbacks.txt\n"
        + "         - Conditions.txt\n" + "         - EasyTaintWrapperSource.txt\n"
        + "         - SourcesAndSinks.txt\n" + "\n" + "    pcap <directory>:\n"
        + "       Analyzes network-dump.pcap in the second-level subdirectories of the specified directory\n"
        + "\n" + "    learn <lang> <textfile>:\n"
        + "       learns a sentence detector model for language lang analyzing sentences\n"
        + "       from the given text file, one per line");
  }

  private static void pcapAnalysis(String[] args) throws IOException {
    File dir = new File(args[1]);

    TextClassifierCollection textClassifierCollection = Factory.createClassifierCollection();
    HtmlScanner htmlScanner = new HtmlScanner(textClassifierCollection);
    TrafficScanner trafficScanner = new TrafficScanner(htmlScanner);

    htmlScanner.setAcceptanceStrategy(Factory.createAcceptanceStrategy());

    for (File resultDir : dir.listFiles()) {
      if (!resultDir.isDirectory() || !resultDir.getName().endsWith(".apk"))
        continue;

      File innerResultDir = resultDir.listFiles()[0];

      try {
        trafficScanner.setPcap(new File(innerResultDir, "network-dump.pcap"));

        AcceptanceStrategy.Result result = trafficScanner.analyze();

        System.out.println(String.format("%s - Detected: %b ; Score: %f", resultDir.getName(),
            result.isAccepted(), result.getScore()));
      } catch (Exception e) {
      }
    }
  }

  private static void learnSentenceDetector(String[] args) throws IOException {
    File trainingFile = new File(args[2]);
    String language = args[1];

    Charset charset = Charset.forName("UTF-8");
    ObjectStream<String> lineStream = new PlainTextByLineStream(new FileInputStream(trainingFile), charset);
    ObjectStream<SentenceSample> sampleStream = new SentenceSampleStream(lineStream);

    SentenceModel model;

    try {
      model = SentenceDetectorME.train(language, sampleStream, true, null, TrainingParameters.defaultParams());
    } finally {
      sampleStream.close();
    }

    File modelFile = new File(Globals.MODELS_DIRECTORY, language + "-sent.bin");
    OutputStream modelStream = null;

    try {
      modelStream = new BufferedOutputStream(new FileOutputStream(modelFile));
      model.serialize(modelStream);
    } finally {
      if (modelStream != null)
        modelStream.close();
    }
  }

  private static String sanitize(String str) {
    return str.trim().replace("\"", "");
  }
}
