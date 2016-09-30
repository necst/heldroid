package it.polimi.elet.necst.heldroid.ransomware.locking;

import it.polimi.elet.necst.heldroid.smali.SmaliSimulator;
import it.polimi.elet.necst.heldroid.smali.core.SmaliClass;
import it.polimi.elet.necst.heldroid.smali.core.SmaliMethod;
import it.polimi.elet.necst.heldroid.smali.names.SmaliClassName;
import it.polimi.elet.necst.heldroid.smali.names.SmaliMemberName;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliIfStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliReturnStatement;
import it.polimi.elet.necst.heldroid.smali.statements.SmaliStatement;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.Collection;

public class DrawOverLockingStrategy extends SmaliLockingStrategy {
    private static final String PERMISSION_TAG = "uses-permission";
    private static final String NAME_ATTRIBUTE = "android:name";
    private static final String SYSTEM_ALERT_WINDOW = "android.permission.SYSTEM_ALERT_WINDOW";

    private static final String KEY_CODE_PARAMETER = "p1";
    private static final String EQUAL = "eq";
    private static final String NOT_EQUAL = "ne";

    private static final SmaliMemberName ON_KEY_DOWN = new SmaliMemberName("Lcom/example/testlock/MainActivity$mainActivity;->onKeyDown");
    private static final SmaliMemberName ON_KEY_UP = new SmaliMemberName("Lcom/example/testlock/MainActivity$mainActivity;->onKeyUp");
    private static final SmaliClassName ACTIVITY = new SmaliClassName("Landroid/app/Activity;");

    private static Collection<String> backButtonCodes, homeButtonCodes, zeroCodes;

    static {
        backButtonCodes = new ArrayList<String>();
        backButtonCodes.add("0x04");
        backButtonCodes.add("0x4");
        backButtonCodes.add("4");

        homeButtonCodes = new ArrayList<String>();
        homeButtonCodes.add("0x03");
        homeButtonCodes.add("0x3");
        homeButtonCodes.add("3");

        zeroCodes = new ArrayList<String>();
        zeroCodes.add("0x00");
        zeroCodes.add("0x0");
        zeroCodes.add("0");
    }

    private DocumentBuilderFactory dbFactory;
    private DocumentBuilder db;

    public DrawOverLockingStrategy() throws ParserConfigurationException {
        super();

        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.db = dbFactory.newDocumentBuilder();
    }

    @Override
    protected boolean detectStrategy() {
        boolean drawOver = hasDrawOverPermission();
        boolean suppress = suppressesNavigation();

        this.setDetectionReport(String.format("Suppresses navigation: %b, Has draw-over permission: %b", suppress, drawOver));

        return drawOver;
    }

    private boolean hasDrawOverPermission() {
        try {
            Document document = db.parse(target.getAndroidManifest());
            Element root = document.getDocumentElement();

            Collection<Element> permissions = Xml.getElementsByTagName(root, PERMISSION_TAG);

            for (Element permission : permissions) {
                if (!permission.hasAttribute(NAME_ATTRIBUTE))
                    continue;

                String name = permission.getAttribute(NAME_ATTRIBUTE);

                if (name.equals(SYSTEM_ALERT_WINDOW))
                    return true;
            }

            return false;
        } catch (Exception e) {
            return true;
        }
    }

    private boolean suppressesNavigation() {
        Collection<SmaliClass> activities = loader.getSubclassesOf(ACTIVITY);

        for (SmaliClass activity : activities)
            if (suppressesNavigation(activity))
                return true;

        return false;
    }

    private boolean suppressesNavigation(SmaliClass activityClass) {
        SmaliMethod onKeyDown = activityClass.getMethodByName(ON_KEY_DOWN);
        SmaliMethod onKeyUp = activityClass.getMethodByName(ON_KEY_UP);

        if ((onKeyDown != null) && suppressesNavigation(onKeyDown))
            return true;

        if (onKeyUp != null)
            return suppressesNavigation(onKeyUp);

        return false;
    }

    private boolean suppressesNavigation(SmaliMethod target) {
        final SmaliSimulator simulator = SmaliSimulator.on(target);

        final Wrapper<Boolean> comparisonFound = new Wrapper<Boolean>(false);
        final Wrapper<Boolean> navigationSuppressed = new Wrapper<Boolean>(false);

        simulator.addHandler(SmaliIfStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliIfStatement ifStatement = (SmaliIfStatement)statement;
                String qualifier = ifStatement.getQualifier();

                if (!qualifier.equals(EQUAL) && !qualifier.equals(NOT_EQUAL))
                    return (comparisonFound.value = false);

                String otherRegister = null;

                if (ifStatement.getRegister1().equals(KEY_CODE_PARAMETER))
                    otherRegister = ifStatement.getRegister2();
                else if (ifStatement.getRegister2().equals(KEY_CODE_PARAMETER))
                    otherRegister = ifStatement.getRegister1();
                else
                    return (comparisonFound.value = false);

                Collection<String> values = simulator.getPossibleValues(otherRegister);

                for (String value : values)
                    if (homeButtonCodes.contains(value) || backButtonCodes.contains(value)) {
                        comparisonFound.value = true;

                        if (qualifier.equals(EQUAL))
                            return true;
                        else
                            return false;
                    }

                return (comparisonFound.value = false);
            }
        });

        simulator.addHandler(SmaliReturnStatement.class, new SmaliSimulator.StatementHandler() {
            @Override
            public boolean statementReached(SmaliStatement statement) {
                SmaliReturnStatement returnStatement = (SmaliReturnStatement)statement;

                if (returnStatement.getRegister() == null)
                    return false;

                String register = returnStatement.getRegister();
                Collection<String> values = simulator.getPossibleValues(register);

                for (String value : values)
                    if (!zeroCodes.contains(value)) // Everything different from zero is true
                        return (navigationSuppressed.value = true);

                return false;
            }
        });

        simulator.simulate();

        return navigationSuppressed.value;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected String strategyName() {
    	return "DrawOver";
    }
}
