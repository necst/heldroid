package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassification;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifier;
import it.polimi.elet.necst.heldroid.ransomware.text.classification.TextClassifierCollection;
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import it.polimi.elet.necst.heldroid.utils.Xml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.util.List;

public class XmlLayoutScanner extends ResourceScanner {
    private static final int MIN_STRING_LENGTH = 30;
    private static final String TEXT_ATTRIBUTE = "android:text";

    private DocumentBuilderFactory dbFactory;
    private DocumentBuilder db;

    public XmlLayoutScanner(TextClassifierCollection classifierCollection) throws ParserConfigurationException {
        super(classifierCollection);

        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.db = dbFactory.newDocumentBuilder();
    }

    @Override
    protected TextClassification findRansomwareText() {
        List<File> layoutDirectories = this.getApkResourceDirectories("layout");
        TextClassification finalClassification = TextClassification.empty();

        for (File layoutDirectory : layoutDirectories)
            for (File layout : FileSystem.listFiles(layoutDirectory, ".xml")) {
                TextClassification layoutTextClassification = this.findRansomwareText(layout);
                finalClassification.append(layoutTextClassification);
            }

        return finalClassification;
    }

    protected TextClassification findRansomwareText(File xmlLayout) {
        try {
            Document document = db.parse(xmlLayout);
            Element root = document.getDocumentElement();

            TextClassification result = this.classifyElementText(root, TextClassification.empty());
            
            extractLikelihood(xmlLayout, result);
            result.setFileClassification(getFileClassification());
            return result;
        } catch (Exception e) {
            return TextClassification.empty();
        }
    }

    protected TextClassification classifyElementText(Element element, TextClassification totalClassification) {
        String text = element.getAttribute(TEXT_ATTRIBUTE);

        if (isSuitableForClassification(text)) {
            TextClassifier textClassifier = this.getTextClassifierFor(text);

            if (textClassifier != null) {
                TextClassification textClassification = textClassifier.classify(text);
                totalClassification.append(textClassification);
            }
        }

        for (Element child : Xml.getChildElements(element))
            this.classifyElementText(child, totalClassification);

        return totalClassification;
    }
}
