package it.polimi.elet.necst.heldroid.xml.manifest;

import it.polimi.elet.necst.heldroid.utils.Xml;
import it.polimi.elet.necst.heldroid.xml.ParsingException;
import it.polimi.elet.necst.heldroid.xml.resources.StringResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class DomManifestAnalyzer implements ManifestAnalyzer {
    private DocumentBuilderFactory dbFactory;

    private List<String> permissions, intentFilters, usedFeatures;
    private String packageName, applicationName, applicationDescription;
    private StringResource stringResource;

    public DomManifestAnalyzer(StringResource stringResource) {
        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.stringResource = stringResource;
        this.permissions = new ArrayList<String>();
        this.intentFilters = new ArrayList<String>();
        this.usedFeatures = new ArrayList<String>();
    }

    @Override
    public ManifestAnalysisReport analyze(File manifestFile) throws ParsingException {
        try {
            DocumentBuilder db = dbFactory.newDocumentBuilder();
            Document document = db.parse(manifestFile);

            document.getDocumentElement().normalize();

            this.clearStoredData();

            this.analyzeManifest(document);
            this.analyzePermissions(document);
            this.analyzeIntentFilters(document);
            this.analyzeUsedFeatures(document);

            return new ManifestAnalysisReport() {
                @Override
                public String getPackageName() {
                    return packageName;
                }

                @Override
                public String getApplicationName() {
                    return applicationName;
                }

                @Override
                public String getApplicationDescription() { return applicationDescription; }

                @Override
                public Collection<String> getPermissions() {
                    return permissions;
                }

                @Override
                public Collection<String> getIntentFilters() { return intentFilters; }

                @Override
                public Collection<String> getUsedFeatures() { return usedFeatures; }
            };
        } catch (Exception e) {
            throw new ParsingException(e);
        }
    }

    private void clearStoredData() {
        this.packageName = "";
        this.applicationName = "";
        this.applicationDescription = "";
        this.permissions.clear();
        this.intentFilters.clear();
        this.usedFeatures.clear();
    }

    private void analyzeManifest(Document document) {
        // Gets the <manifest> node of the xml, which is the document main element
        Element manifestElement = document.getDocumentElement();

        // Checks if the package attribute exists: in that case, it contains the package name associated with
        // the analyzed application
        if (manifestElement.hasAttribute(ManifestStrings.PACKAGE_ATTRIBUTE))
            packageName = manifestElement.getAttribute(ManifestStrings.PACKAGE_ATTRIBUTE);

        // Gets the <application> tag, child of <manifest>. It is a mandatory node for every manifest but
        // the method of course returns a list which we have to check for consistency
        NodeList applicationTags = manifestElement.getElementsByTagName(ManifestStrings.APPLICATION_TAG);

        if (applicationTags.getLength() > 0) {
            Element applicationElement = (Element) applicationTags.item(0);
            String label = this.getStringAttribute(applicationElement, ManifestStrings.LABEL_ATTRIBUTE);
            String description = this.getStringAttribute(applicationElement, ManifestStrings.DESCRIPTION_ATTRIBUTE);

            if (label != null)
                this.applicationName = label;

            if (description != null)
                this.applicationDescription = description;
        }
    }

    private String getStringAttribute(Element currentElement, String attributeName) {
        // Looks at the attribute only if it exists
        if (currentElement.hasAttribute(attributeName)) {
            String value = currentElement.getAttribute(attributeName);

            // If the value refers to a string resource (@string/name), we have to look for it among the string
            // resources declared in xml files in the res folder, that here we supposed to have in stringResource
            if (StringAttribute.isResourceReference(value)) {
                String reference = StringAttribute.getReferenceName(value);
                return this.stringResource.getValue(reference);
            }

            // Otherwise, the plain value is returned
            return value;
        }

        // No attribute exists
        return null;
    }

    private void analyzePermissions(Document document) {
        Collection<Element> permissionElements = Xml.getElementsByTagName(document.getDocumentElement(), ManifestStrings.PERMISSION_TAG);

        for (Element permissionElement : permissionElements) {
            if (!permissionElement.hasAttribute(ManifestStrings.NAME_ATTRIBUTE))
                continue;

            String name = permissionElement.getAttribute(ManifestStrings.NAME_ATTRIBUTE);

            permissions.add(name);
        }
    }

    private void analyzeIntentFilters(Document document) {
        Collection<Element> intentFilterElements = Xml.getElementsByTagName(document.getDocumentElement(), ManifestStrings.INTENT_FILTER_TAG);

        for (Element intentFilterElement : intentFilterElements) {
            Collection<Element> actionElements = Xml.getElementsByTagName(intentFilterElement, ManifestStrings.ACTION_TAG);

            for (Element actionElement : actionElements) {
                if (!actionElement.hasAttribute(ManifestStrings.NAME_ATTRIBUTE))
                    continue;

                intentFilters.add(actionElement.getAttribute(ManifestStrings.NAME_ATTRIBUTE));
            }
        }
    }

    private void analyzeUsedFeatures(Document document) {
        Collection<Element> usedFeatureElements = Xml.getElementsByTagName(document.getDocumentElement(), ManifestStrings.USES_FEATURE_TAG);

        for (Element usedFeatureElement : usedFeatureElements) {
            if (!usedFeatureElement.hasAttribute(ManifestStrings.NAME_ATTRIBUTE))
                continue;

            String name = usedFeatureElement.getAttribute(ManifestStrings.NAME_ATTRIBUTE);

            usedFeatures.add(name);
        }
    }
}
