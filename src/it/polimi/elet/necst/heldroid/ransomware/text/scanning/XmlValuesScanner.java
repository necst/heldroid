package it.polimi.elet.necst.heldroid.ransomware.text.scanning;

import it.polimi.elet.necst.heldroid.ransomware.text.SupportedLanguage;
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
import java.util.ArrayList;
import java.util.List;

public class XmlValuesScanner extends ResourceScanner {
    private static final int MIN_STRING_LENGTH = 30;

    private static final String RESOURCES_TAG = "resources";
    private static final String STRING_TAG = "string";
    private static final String STRING_ARRAY_TAG = "string-array";
    private static final String ITEM_TAG = "item";

    private DocumentBuilderFactory dbFactory;
    private DocumentBuilder db;

    public XmlValuesScanner(TextClassifierCollection classifierCollection) throws ParserConfigurationException {
        super(classifierCollection);

        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.db = dbFactory.newDocumentBuilder();
    }

    @Override
    protected TextClassification findRansomwareText() {
        TextClassification finalClassification = TextClassification.empty();
        File res = this.getApkResourceDirectory();
        File valuesDir = new File(res, "values");

        if (valuesDir.exists()) {
            for (File stringValuesFile : FileSystem.listFiles(valuesDir, ".xml")) {
                TextClassification valuesTextClassification = this.findRansomwareText(stringValuesFile, null);
                finalClassification.append(valuesTextClassification);
            }
        }

        for (SupportedLanguage supportedLanguage : textClassifierCollection.getSupposedLanguages()) {
            File valuesLangDir = new File(res, "values-" + supportedLanguage.getCode());

            if (!valuesDir.exists())
                continue;

            TextClassifier langTextClassifier = textClassifierCollection.get(supportedLanguage);

            for (File stringValuesFile : FileSystem.listFiles(valuesDir, ".xml")) {
                TextClassification valuesTextClassification = this.findRansomwareText(stringValuesFile, langTextClassifier);
                finalClassification.append(valuesTextClassification);
            }
        }

        return finalClassification;
    }

    protected TextClassification findRansomwareText(File stringValuesFile, TextClassifier knownClassifier) {
    	try {
            Document document = db.parse(stringValuesFile);
            Element root = document.getDocumentElement();
            TextClassification result = this.classifyElementText(root, knownClassifier);   
            
            extractLikelihood(stringValuesFile, result);
            result.setFileClassification(getFileClassification());
            return result;
        } catch (Exception e) {
            return TextClassification.empty();
        }
    }

    protected TextClassification classifyElementText(Element root, TextClassifier knownClassifier) {
        if (!root.getTagName().equals(RESOURCES_TAG))
            return null;

        TextClassification totalClassification = TextClassification.empty();
        List<Element> children = Xml.getChildElements(root);

        for (Element child : children) {
            List<String> contents = new ArrayList<String>();

            if (child.getTagName().equals(STRING_TAG)) {
                String content = child.getTextContent();
                if (isSuitableForClassification(content))
                    contents.add(content);

            } else if (child.getTagName().equals(STRING_ARRAY_TAG)) {
                for (Element item : Xml.getChildElements(child)) {
                    if (!item.getTagName().equals(ITEM_TAG))
                        continue;

                    String content = item.getTextContent();
                    if (isSuitableForClassification(content))
                        contents.add(content);
                }
            }

            for (String content : contents) {
                TextClassifier textClassifier = (knownClassifier != null) ? knownClassifier : this.getTextClassifierFor(content);

                if (textClassifier != null) {
                    TextClassification textClassification = textClassifier.classify(content);
                    totalClassification.append(textClassification);
                }
            }
        }

        return totalClassification;
    }
}
