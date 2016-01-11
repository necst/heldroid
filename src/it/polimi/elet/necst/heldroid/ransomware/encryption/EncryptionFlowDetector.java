package it.polimi.elet.necst.heldroid.ransomware.encryption;


import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.source.AndroidSourceSinkManager.LayoutMatchingMode;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;

public class EncryptionFlowDetector {
    private static final String PERMISSION_TAG = "uses-permission";
    private static final String NAME_ATTRIBUTE = "android:name";
    private static final String WRITE_EXTERNAL_STORAGE = "android.permission.WRITE_EXTERNAL_STORAGE";

    private static final String SOURCE_SINKS_FILE_NAME = "SourcesAndSinks.txt";
    private static final String TAINT_WRAPPER_FILE_NAME = "EasyTaintWrapperSource.txt";

    private static final int FLOW_TIMEOUT = 1*60; // seconds

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

            for (Element permission : permissions) {
                if (!permission.hasAttribute(NAME_ATTRIBUTE))
                    continue;

                String name = permission.getAttribute(NAME_ATTRIBUTE);

                if (name.equals(WRITE_EXTERNAL_STORAGE))
                    canWrite = true;

                /*
                 * Any app that declares the WRITE_EXTERNAL_STORAGE permission
                 * is implicitly granted READ_EXTERNAL_STORAGE permission.
                 * So there's no need to check READ_EXTERNAL_STORAGE permission.
                 */
//                if (canRead && canWrite)
                if (canWrite)
                    return true;
            }

            return false;
        } catch (Exception e) {
            return true;
        }
    }

    public Wrapper<EncryptionResult> detect() {
        if (target == null)
            throw new NullPointerException("Target not set!");

        if (androidPlatformsDir == null)
            throw new NullPointerException("Android platforms dir not set!");

        final Wrapper<EncryptionResult> result = new Wrapper<>(new EncryptionResult());
        result.value.setWritable(this.hasRwPermission());
        
        if (!this.hasRwPermission()) {
            System.out.println("APK has no RW permission");
//        	return false;
            return result;
        }

//        final Wrapper<InfoflowResults> res = new Wrapper<InfoflowResults>(null);

//        Logging.suppressAll();

        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.submit(new Runnable() {
            @Override
            public void run() {
                SetupApplication app;

                try {
                    app = initAnalysis();
//                    if (res != null)
//                        res.value = app.runInfoflow();
                    if (result != null && result.value != null) {
                    	result.value.setInfoFlowResults(app.runInfoflow());
                    }
                } catch (Throwable e) { }
            }
        });
        executor.shutdown();
        
        try {
            if (!executor.awaitTermination(FLOW_TIMEOUT, TimeUnit.SECONDS))
                executor.shutdownNow();
        } catch (InterruptedException e) { }

//        Logging.restoreAll();

//        boolean result = (res.value != null) && (res.value.getResults().size() > 0);
        return result;
    }

    private SetupApplication initAnalysis() {
        SetupApplication app = new SetupApplication(androidPlatformsDir.getAbsolutePath(), target.getOriginalApk().getAbsolutePath() );
        InfoflowAndroidConfiguration config = app.getConfig();
        
        /* We are interested in paths too */
        InfoflowAndroidConfiguration.setOneResultPerAccessPath(true);
        /* Do not merge paths */
        InfoflowAndroidConfiguration.setPathAgnosticResults(true);
  
        InfoflowAndroidConfiguration.setAccessPathLength(5);
        
        config.setStopAfterFirstFlow(true);
        config.setEnableImplicitFlows(true);
        config.setEnableStaticFieldTracking(true);
        config.setEnableCallbacks(true);
        config.setEnableExceptionTracking(true);
        config.setLayoutMatchingMode(LayoutMatchingMode.MatchSensitiveOnly);
        config.setFlowSensitiveAliasing(true);
        config.setPathBuilder(DefaultPathBuilderFactory.PathBuilder.ContextSensitive);
        config.setComputeResultPaths(true);

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
