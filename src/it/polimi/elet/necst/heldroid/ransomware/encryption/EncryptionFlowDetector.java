package it.polimi.elet.necst.heldroid.ransomware.encryption;


import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;
import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.utils.Logging;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import soot.jimple.infoflow.android.AndroidSourceSinkManager;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory;
import soot.jimple.infoflow.handlers.ResultsAvailableHandler;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.solver.IInfoflowCFG;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class EncryptionFlowDetector {
    private static final String PERMISSION_TAG = "uses-permission";
    private static final String NAME_ATTRIBUTE = "android:name";
    private static final String WRITE_EXTERNAL_STORAGE = "android.permission.WRITE_EXTERNAL_STORAGE";
    private static final String READ_EXTERNAL_STORAGE = "android.permission.READ_EXTERNAL_STORAGE";

    private static final String SOURCE_SINKS_FILE_NAME = "SourcesAndSinks.txt";
    private static final String TAINT_WRAPPER_FILE_NAME = "EasyTaintWrapperSource.txt";

    private static final int FLOW_TIMEOUT = 20; // seconds

    private DocumentBuilderFactory dbFactory;
    private DocumentBuilder db;
    private DecodedPackage target;
    private File androidPlatformsDir;

    public void setTarget(DecodedPackage target) {
        this.target = target;
    }

    public void setAndroidPlatformsDir(File androidPlatformsDir) {
        this.androidPlatformsDir = androidPlatformsDir;
    }

    public EncryptionFlowDetector() throws ParserConfigurationException {
        this.dbFactory = DocumentBuilderFactory.newInstance();
        this.db = dbFactory.newDocumentBuilder();
    }

    private boolean hasRwPermission() {
        try {
            Document document = db.parse(target.getAndroidManifest());
            Element root = document.getDocumentElement();

            Collection<Element> permissions = Xml.getElementsByTagName(root, PERMISSION_TAG);
            boolean canWrite = false;
            boolean canRead = false;

            for (Element permission : permissions) {
                if (!permission.hasAttribute(NAME_ATTRIBUTE))
                    continue;

                String name = permission.getAttribute(NAME_ATTRIBUTE);

                if (name.equals(WRITE_EXTERNAL_STORAGE))
                    canWrite = true;
                else if (name.equals(READ_EXTERNAL_STORAGE))
                    canRead = true;

                if (canRead && canWrite)
                    return true;
            }

            return false;
        } catch (Exception e) {
            return true;
        }
    }

    public boolean detect() {
        if (target == null)
            throw new NullPointerException("Target not set!");

        if (androidPlatformsDir == null)
            throw new NullPointerException("Android platforms dir not set!");

        if (!this.hasRwPermission())
            return false;


        final Wrapper<InfoflowResults> res = new Wrapper<InfoflowResults>(null);

        Logging.suppressAll();

        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.submit(new Runnable() {
            @Override
            public void run() {
                SetupApplication app;

                try {
                    app = initAnalysis();
                    if (res != null)
                        res.value = app.runInfoflow();
                } catch (Throwable e) { }
            }
        });
        executor.shutdown();
        
        try {
            if (!executor.awaitTermination(FLOW_TIMEOUT, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) { }

        Logging.restoreAll();

        return (res.value != null) && (res.value.getResults().size() > 0);
    }

    private SetupApplication initAnalysis() {
        SetupApplication app = new SetupApplication(androidPlatformsDir.getAbsolutePath(), target.getOriginalApk().getAbsolutePath() );
        app.setStopAfterFirstFlow(true);
        app.setEnableImplicitFlows(false);
        app.setEnableStaticFieldTracking(true);
        app.setEnableCallbacks(true);
        app.setEnableExceptionTracking(true);
        app.setAccessPathLength(5);
        app.setLayoutMatchingMode(AndroidSourceSinkManager.LayoutMatchingMode.MatchSensitiveOnly);
        app.setFlowSensitiveAliasing(true);
        app.setPathBuilder(DefaultPathBuilderFactory.PathBuilder.ContextInsensitiveSourceFinder);
        app.setComputeResultPaths(true);

        EasyTaintWrapper easyTaintWrapper = null;

        try {
            easyTaintWrapper = new EasyTaintWrapper(TAINT_WRAPPER_FILE_NAME);
        } catch (IOException e) { }

        easyTaintWrapper.setAggressiveMode(false);
        app.setTaintWrapper(easyTaintWrapper);

        try {
            app.calculateSourcesSinksEntrypoints(SOURCE_SINKS_FILE_NAME);
        } catch (Exception e) { }

        return app;
    }

    public interface FlowResultHandler {
        void onResult(boolean found);
    }
}
