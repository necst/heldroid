package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import java.io.File;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifier;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;
import it.polimi.elet.necst.heldroid.utils.FileSystem;

public class HtmlScanner extends ResourceScanner {
    private static final long MAX_HTML_FILE_SIZE = 100000;

    public HtmlScanner(TextClassifierCollection textClassifierCollection1) {
        super(textClassifierCollection1);
    }

    public AcceptanceStrategy.Result evaluate(File htmlFile) {
        try {
            TextClassification classification = this.findRandomwareText(htmlFile);
            return acceptanceStrategy.accepts(classification);
        } catch (Exception e) {
            e.printStackTrace();
            return AcceptanceStrategy.fail();
        }
    }

    @Override
    protected TextClassification findRansomwareText() {
        TextClassification finalClassification = TextClassification.empty();

        for (File htmlFile : FileSystem.listFilesRecursively(this.unpackedApkDirectory, ".html")) {
            TextClassification htmlTextClassification = this.findRandomwareText(htmlFile);
            finalClassification.append(htmlTextClassification);
        }

        return finalClassification;
    }

    protected TextClassification findRandomwareText(File htmlFile)  {
        if (htmlFile.length() > MAX_HTML_FILE_SIZE)
            return TextClassification.empty();

        try {
            Document document = Jsoup.parse(htmlFile, "UTF-8");
            Element body = document.body();
            TextClassification result = this.classifyElementText(body, TextClassification.empty());
            
            extractLikelihood(htmlFile, result);
            result.setFileClassification(getFileClassification());
            return result;
        } catch (Exception e) {
            return TextClassification.empty();
        }
    }

    protected TextClassification classifyElementText(Element element, TextClassification totalClassification) {
        String text = element.ownText();

        if (isSuitableForClassification(text)) {
            TextClassifier textClassifier = this.getTextClassifierFor(text);

            if (textClassifier != null) {
                TextClassification textClassification = textClassifier.classify(text);
                totalClassification.append(textClassification);
            }
        }

        for (Element child : element.children())
            this.classifyElementText(child, totalClassification);

        return totalClassification;
    }
}
