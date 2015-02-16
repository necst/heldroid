package it.polimi.elet.necst.heldroid.ransomware;

import it.polimi.elet.necst.heldroid.ransomware.emulation.TrafficScanner;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.ransomware.locking.AdminLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.locking.DialogLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.locking.DrawOverLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.locking.MultiLockingStrategy;
import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.*;
import it.polimi.elet.necst.heldroid.ransomware.text.scanning.*;
import opennlp.tools.sentdetect.SentenceDetector;
import opennlp.tools.sentdetect.SentenceDetectorME;
import opennlp.tools.sentdetect.SentenceModel;
import opennlp.tools.stemmer.Stemmer;
import opennlp.tools.stemmer.snowball.SnowballStemmer;
import org.jnetpcap.protocol.application.Html;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.List;

public class Factory {
    public static EncryptionFlowDetector createEncryptionFlowDetector() throws ParserConfigurationException {
        EncryptionFlowDetector encryptionFlowDetector = new EncryptionFlowDetector();
        encryptionFlowDetector.setAndroidPlatformsDir(Globals.ANDROID_PLATFORMS_DIRECTORY);
        return encryptionFlowDetector;
    }


    public static TrafficScanner createTrafficScanner() {
        HtmlScanner htmlScanner = new HtmlScanner(createClassifierCollection());
        htmlScanner.setAcceptanceStrategy(createAcceptanceStrategy());
        return new TrafficScanner(htmlScanner);
    }


    public static MultiLockingStrategy createLockingStrategy() throws ParserConfigurationException {
        MultiLockingStrategy allLockingStratgies = new MultiLockingStrategy();

        allLockingStratgies.add(new AdminLockingStrategy());
        allLockingStratgies.add(new DrawOverLockingStrategy());
        allLockingStratgies.add(new DialogLockingStrategy());

        return allLockingStratgies;
    }


    public static MultiResourceScanner createResourceScanner() throws ParserConfigurationException {
        TextClassifierCollection textClassifierCollection = createClassifierCollection();
        MultiResourceScanner multiResourceScanner = new MultiResourceScanner(textClassifierCollection);

        multiResourceScanner.add(new XmlLayoutScanner(textClassifierCollection));
        multiResourceScanner.add(new XmlValuesScanner(textClassifierCollection));
        multiResourceScanner.add(new HtmlScanner(textClassifierCollection));
        multiResourceScanner.setAcceptanceStrategy(createAcceptanceStrategy());

        return multiResourceScanner;
    }

    public static AcceptanceStrategy createAcceptanceStrategy() {
        return new AcceptanceStrategy() {
            @Override
            public Result accepts(TextClassification textClassification) {
                List<SentenceClassification> accuses = textClassification.findAllSentences(Globals.MIN_LIKELIHOOD_THRESHOLD, "threat", "porn", "law", "copyright");
                List<SentenceClassification> moneypaks = textClassification.findAllSentences(Globals.MIN_LIKELIHOOD_THRESHOLD, "moneypak");

                double accuseScore = weightNumerosity(accuses);
                double moneypakScore = weightNumerosity(moneypaks);

                Result result = new Result();

                result.setAccepted((moneypakScore >= Globals.MIN_LIKELIHOOD_THRESHOLD) && (accuseScore >= Globals.MIN_LIKELIHOOD_THRESHOLD));
                result.setScore(accuseScore);
                result.setComment(
                        String.format("Threat: %f, Porn: %f, Law: %f, Copyright: %f, Moneypak: %f",
                                textClassification.maxLikelihood("threat"),
                                textClassification.maxLikelihood("porn"),
                                textClassification.maxLikelihood("law"),
                                textClassification.maxLikelihood("copyright"),
                                textClassification.maxLikelihood("moneypak")));

                return result;
            }
        };
    }

    private static double weightNumerosity(List<SentenceClassification> sentences) {
        double max = 0;
        double sum = 0;

        for (SentenceClassification s : sentences) {
            double t = computeThreshold(s);

            if (s.getLikelihood() >= t) {
                sum += (s.getLikelihood() - t);
                if (s.getLikelihood() > max)
                    max = s.getLikelihood();
            }
        }

        if (max < Globals.MIN_LIKELIHOOD_THRESHOLD)
            return 0;

        return max + (1 - max) * (1 - Math.exp(-sum));
    }

    private static double computeThreshold(SentenceClassification s) {
        double stemCoefficient = (s.getProducedStemsCount() - Globals.MIN_PRODUCED_STEMS) / (Globals.MAX_PRODUCED_STEMS - Globals.MIN_PRODUCED_STEMS);

        stemCoefficient = Math.max(0, Math.min(1, stemCoefficient));

        return Globals.MAX_LIKELIHOOD_THRESHOLD - stemCoefficient * (Globals.MAX_LIKELIHOOD_THRESHOLD - Globals.MIN_LIKELIHOOD_THRESHOLD);
    }


    public static TextClassifierCollection createClassifierCollection() {
        TextClassifier englishClassifier = createClassifier(SupportedLanguage.ENGLISH);
        TextClassifier russianClassifier = createClassifier(SupportedLanguage.RUSSIAN);
        TextClassifier spanishClassifier = createClassifier(SupportedLanguage.SPANISH);
        TextClassifierCollection textClassifierCollection = new TextClassifierCollection();

        textClassifierCollection.add(SupportedLanguage.ENGLISH, englishClassifier);
        textClassifierCollection.add(SupportedLanguage.RUSSIAN, russianClassifier);
        textClassifierCollection.add(SupportedLanguage.SPANISH, spanishClassifier);

        return textClassifierCollection;
    }

    private static TextClassifier createClassifier(SupportedLanguage language) {
        StopWordList swc = StopWordList.fromFile(new File(Globals.STOP_WORDS_DIRECTORY, language.getName() + ".txt"));
        Stemmer stm = new SnowballStemmer(language.getStemmerAlgorithm());

        try {
            InputStream modelStream = new FileInputStream(new File(Globals.MODELS_DIRECTORY, language.getCode() + "-sent.bin"));
            SentenceModel model = new SentenceModel(modelStream);
            SentenceDetector sd = new SentenceDetectorME(model);
            Segmenter segmenter = new Segmenter(swc, stm, sd);
            GenericTextClassifier classifier = new GenericTextClassifier(segmenter);

            File trainingData = new File(Globals.TRAINING_DATA_DIRECTORY, language.getCode() + "-ransom.csv");
            BufferedReader reader = new BufferedReader(new FileReader(trainingData));
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.equals(""))
                    continue;

                int commaIndex = line.indexOf(',');
                String category = sanitize(line.substring(0, commaIndex - 1));
                String text = sanitize(line.substring(commaIndex + 1));

                classifier.teach(category, text);
            }

            reader.close();

            return classifier;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String sanitize(String str) {
        return str.trim().replace("\"", "");
    }
}
