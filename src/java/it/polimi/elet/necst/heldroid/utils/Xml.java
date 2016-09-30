package it.polimi.elet.necst.heldroid.utils;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Xml {
    public static Element getChildElement(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);

        if (nodes.getLength() == 0)
            return null;

        Node node = nodes.item(0);

        if (node.getNodeType() != Node.ELEMENT_NODE)
            return null;

        return (Element) node;
    }

    public static List<Element> getChildElements(Element parent) {
        List<Element> result = new ArrayList<Element>();
        NodeList nodes = parent.getChildNodes();

        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE)
                result.add((Element)node);
        }

        return result;
    }

    public static Collection<Element> getElementsByTagName(Element parent, String tagName) {
        NodeList backtrackNodes = parent.getElementsByTagName(tagName);
        List<Element> results = new ArrayList<Element>();

        for (int i = 0; i < backtrackNodes.getLength(); i++) {
            Node node = backtrackNodes.item(i);

            if (node.getNodeType() != Node.ELEMENT_NODE)
                continue;

            Element element = (Element) node;

            results.add(element);
        }

        return results;
    }
}
