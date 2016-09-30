package it.polimi.elet.necst.heldroid.xml.resources;

import it.polimi.elet.necst.heldroid.xml.ParsingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class DomStringResourceParser implements StringResourceParser {
    protected static final String RESOURCES_TAG = "resources";
    protected static final String STRING_TAG = "string";
    protected static final String NAME_ATTRIBUTE = "name";

    private DocumentBuilderFactory dbFactory;

    public DomStringResourceParser() {
        this.dbFactory = DocumentBuilderFactory.newInstance();
    }

    @Override
    public StringResource parse(File resourceFile) throws ParsingException {
        StringDictionary dictionary = new StringDictionary();

        try {
            DocumentBuilder db = dbFactory.newDocumentBuilder();
            Document document = db.parse(resourceFile);
            Element resourceElement = document.getDocumentElement();

            resourceElement.normalize();

            // The top-level node of a valid resource file must be <resources>
            if (!resourceElement.getTagName().equals(RESOURCES_TAG))
                throw new ParsingException("This is not a valid resource xml file.");

            // Then we look for all the <string> tags below
            NodeList stringNodes = resourceElement.getElementsByTagName(STRING_TAG);

            for (int i = 0; i < stringNodes.getLength(); i++) {
                Node stringNode = stringNodes.item(i);

                if (stringNode.getNodeType() != Node.ELEMENT_NODE)
                    continue;

                Element stringElement = (Element) stringNode;

                // Strings with no name cannot be referenced and hence are useless
                if (!stringElement.hasAttribute(NAME_ATTRIBUTE))
                    continue;

                dictionary.add(stringElement.getAttribute(NAME_ATTRIBUTE), stringElement.getTextContent());
            }

            return dictionary;
        } catch (Exception e) {
            throw new ParsingException(e);
        }
    }
}
