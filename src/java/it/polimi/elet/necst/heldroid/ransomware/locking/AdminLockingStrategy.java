package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.smali.SmaliConstantFinder;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AdminLockingStrategy extends SmaliLockingStrategy {
    private static final String PERMISSION_ATTRIBUTE = "android:permission";
    private static final String BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN";
    private static final String RESOURCE_ATTRIBUTE = "android:resource";
    private static final String FORCE_LOCK_TAG = "force-lock";

    private static final String ACTION_ADD_DEVICE_ADMIN = "android.app.action.ADD_DEVICE_ADMIN";
    private static final SmaliMemberName INTENT_CONSTRUCTOR = new SmaliMemberName("Landroid/content/Intent;-><init>");
    private static final int INTENT_CONSTRUCTOR_NAME_PARAMETER_INDEX = 0;

    private static final SmaliMemberName LOCK_NOW = new SmaliMemberName("Landroid/app/admin/DevicePolicyManager;->lockNow");

    private DocumentBuilderFactory dbFactory;
    private DocumentBuilder db;

    public AdminLockingStrategy() throws ParserConfigurationException {
        super();

        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.db = dbFactory.newDocumentBuilder();
    }

    @Override
    protected boolean detectStrategy() {
        boolean lockingPrivilege = true;

        try {
            lockingPrivilege = hasLockingPrivilege();
        } catch (Exception e) { }

        boolean askAdmin = asksForAdmin();
        boolean locks = callsLock();

        this.setDetectionReport(String.format("Has locking privilege: %b, Asks for admin: %b, Calls lock(): %b", lockingPrivilege, askAdmin, locks));

        return lockingPrivilege && asksForAdmin() && callsLock();
    }

    private boolean asksForAdmin() {
        final Wrapper<Boolean> found = new Wrapper<Boolean>(false);

        constantFinder.setHandler(new SmaliConstantFinder.ConstantHandler() {
            @Override
            public boolean constantFound(String value) {
                if (value.contains(ACTION_ADD_DEVICE_ADMIN))
                    return (found.value = true);
                return false;
            }
        });

        constantFinder.searchParameters(INTENT_CONSTRUCTOR, INTENT_CONSTRUCTOR_NAME_PARAMETER_INDEX);

        return found.value;
    }

    private boolean hasLockingPrivilege() throws IOException, SAXException {
        Document document = db.parse(target.getAndroidManifest());
        Element root = document.getDocumentElement();

        Collection<Element> receivers = Xml.getElementsByTagName(root, "receiver");

        for (Element receiver : receivers) {
            if (!receiver.hasAttribute(PERMISSION_ATTRIBUTE))
                continue;

            String permission = receiver.getAttribute(PERMISSION_ATTRIBUTE);

            if (!permission.contains(BIND_DEVICE_ADMIN))
                continue;

            Element metadata = Xml.getChildElement(receiver, "meta-data");

            if ((metadata == null) || !metadata.hasAttribute(RESOURCE_ATTRIBUTE))
                continue;

            String resource = metadata.getAttribute(RESOURCE_ATTRIBUTE);
            File resourceDirectory = new File(target.getDecodedDirectory(), "res");

            if (!resource.startsWith("@"))
                continue;

            int slashIndex = resource.indexOf('/');
            String folderName = resource.substring(1, slashIndex - 1);
            String fileName = resource.substring(slashIndex + 1);
            File metadataXml = new File(new File(resourceDirectory, folderName), fileName);

            if (!metadataXml.exists())
                continue;

            if (this.hasLockingPrivilege(metadataXml))
                return true;
        }

        return false;
    }

    private boolean hasLockingPrivilege(File metadataXml) {
        try {
            Document document = db.parse(metadataXml);
            Collection<Element> forceLock = Xml.getElementsByTagName(document.getDocumentElement(), FORCE_LOCK_TAG);
            return forceLock.size() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean callsLock() {
        List<SmaliMemberName> singleton = new ArrayList<SmaliMemberName>();
        singleton.add(LOCK_NOW);

        boolean[] result = inspector.invocationsExist(singleton);

        return result[0];
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected String strategyName() {
    	return "DeviceAdmin";
    }
}
