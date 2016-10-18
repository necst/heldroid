package it.polimi.elet.necst.heldroid.ransomware.encryption;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
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

import soot.SootClass;
import soot.SootMethod;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.source.AndroidSourceSinkManager.LayoutMatchingMode;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AccessPath.ArrayTaintType;
import soot.jimple.infoflow.data.AccessPathFactory;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory;
import soot.jimple.infoflow.problems.conditions.ConditionParser;
import soot.jimple.infoflow.problems.conditions.ConditionSet;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.infoflow.taintWrappers.TaintWrapperSet;

public class EncryptionFlowDetector {
	private static final String PERMISSION_TAG = "uses-permission";
	private static final String NAME_ATTRIBUTE = "android:name";
	private static final String WRITE_EXTERNAL_STORAGE = "android.permission.WRITE_EXTERNAL_STORAGE";

	private static final String SOURCE_SINKS_FILE_NAME = "SourcesAndSinks.txt";
	private static final String TAINT_WRAPPER_FILE_NAME = "EasyTaintWrapperSource.txt";
  private static final String CONDITIONS_FILE = "Conditions.txt";

	private static final int FLOW_TIMEOUT = 220; // seconds

	private DocumentBuilderFactory dbFactory;
	private DocumentBuilder db;
	private DecodedPackage target;
	private File androidPlatformsDir;

	private ConditionSet conditions;

  private File sourceSinksFilePath;
  private File taintWrapperFilePath;
  private File conditionsFilePath;

	public void setTarget(DecodedPackage target) {
		this.target = target;
	}

	public void setAndroidPlatformsDir(File androidPlatformsDir) {
		this.androidPlatformsDir = androidPlatformsDir;
	}

	public EncryptionFlowDetector()
      throws ParserConfigurationException {

    this.sourceSinksFilePath = new File(SOURCE_SINKS_FILE_NAME);
    this.taintWrapperFilePath = new File(TAINT_WRAPPER_FILE_NAME);
    this.conditionsFilePath = new File(CONDITIONS_FILE);

		this.dbFactory = DocumentBuilderFactory.newInstance();
		this.db = dbFactory.newDocumentBuilder();

		try {
			ConditionParser parser = ConditionParser.fromFile(this.conditionsFilePath.getPath());
			this.conditions = parser.getConditionSet();
		} catch (IOException e) {
			System.err.println("Cannot parse file: Conditions.txt");
			this.conditions = null;
		}
  }

	private boolean hasRwPermission() {
		try {
			Document document = db.parse(target.getAndroidManifest());
			Element root = document.getDocumentElement();

			Collection<Element> permissions = Xml.getElementsByTagName(root,
					PERMISSION_TAG);
			boolean canWrite = false;

			for (Element permission : permissions) {
				if (!permission.hasAttribute(NAME_ATTRIBUTE))
					continue;

				String name = permission.getAttribute(NAME_ATTRIBUTE);

				if (name.equals(WRITE_EXTERNAL_STORAGE))
					canWrite = true;

				/*
				 * Any app that declares the WRITE_EXTERNAL_STORAGE permission
				 * is implicitly granted READ_EXTERNAL_STORAGE permission. So
				 * there's no need to check READ_EXTERNAL_STORAGE permission.
				 */
				// if (canRead && canWrite)
				if (canWrite) {
					return true;
				}
			}

			return false;
		} catch (Exception e) {
			// If we cannot parse the manifest, we assume that the sample has RW
			// permission
			return true;
		}
	}

	public Wrapper<EncryptionResult> detect() {
		if (target == null)
			throw new NullPointerException("Target not set!");

		if (androidPlatformsDir == null)
			throw new NullPointerException("Android platforms dir not set!");

		final Wrapper<EncryptionResult> result = new Wrapper<>(
				new EncryptionResult());
		result.value.setWritable(this.hasRwPermission());

		if (!this.hasRwPermission()) {
			System.out.println("APK has no RW permission");
			// return false;
			return result;
		}

		// final Wrapper<InfoflowResults> res = new
		// Wrapper<InfoflowResults>(null);

		// Logging.suppressAll();

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(new Runnable() {
			@Override
			public void run() {
				SetupApplication app;

				try {
					app = initAnalysis();
					// if (res != null)
					// res.value = app.runInfoflow();
					if (result != null && result.value != null) {
						result.value.setInfoFlowResults(app.runInfoflow());
					}
				} catch (Throwable e) {
					e.printStackTrace();
					result.value.setTimedout(true);
				}
			}
		});

		executor.shutdown();

		try {
			if (!executor.awaitTermination(FLOW_TIMEOUT, TimeUnit.SECONDS)) {
				executor.shutdownNow();
				result.value.setTimedout(true);
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
			result.value.setTimedout(true);
		}
		// Logging.restoreAll();

		// boolean result = (res.value != null) &&
		// (res.value.getResults().size() > 0);
		return result;
	}

	private SetupApplication initAnalysis() {
//		SetupApplication app = new SetupApplication(
//				androidPlatformsDir.getAbsolutePath(), target	.getOriginalApk()
//																.getAbsolutePath());
		 String androidJar = new File(androidPlatformsDir,
         "android-23/android.jar").getAbsolutePath();
		 SetupApplication app = new SetupApplication(androidJar,
		 target.getOriginalApk().getAbsolutePath());
		InfoflowAndroidConfiguration config = app.getConfig();

		InfoflowAndroidConfiguration.setMergeNeighbors(false);
		InfoflowAndroidConfiguration.setPathAgnosticResults(false);
		InfoflowAndroidConfiguration.setOneResultPerAccessPath(true);

		config.setStopAfterFirstFlow(true);
		config.setEnableImplicitFlows(false);
		config.setEnableStaticFieldTracking(true);
		config.setEnableCallbacks(true);
		// Callbacks are not sources
		config.setEnableCallbackSources(false);
		config.setEnableExceptionTracking(false);
		config.setLayoutMatchingMode(LayoutMatchingMode.NoMatch);
		config.setFlowSensitiveAliasing(true);
		config.setPathBuilder(
				DefaultPathBuilderFactory.PathBuilder.ContextSensitive);
		config.setComputeResultPaths(true);
		config.setMaxThreadNum(-1);

		// ForwardCFGNavigator navigator = new ForwardCFGNavigator();
		// navigator.setLoggingEnabled(false);
		// navigator.setIgnoreExceptions(false);
		// navigator.setIgnoreFlowsInSystemPackages(true);
		// config.setCFGNavigator(navigator);

		config.setConditions(conditions);
//		config.setConditionFilename("Conditions.txt");

		EasyTaintWrapper easyTaintWrapper = null;
		TaintWrapperSet taintSet = new TaintWrapperSet();

		try {
			easyTaintWrapper = new EasyTaintWrapper(this.taintWrapperFilePath.getPath());
			taintSet.addWrapper(easyTaintWrapper);
		} catch (IOException e) {
		}

		taintSet.addWrapper(new ITaintPropagationWrapper() {

			@Override
			public boolean supportsCallee(Stmt callSite) {
				if (callSite.containsFieldRef()) {
					InvokeExpr ie = callSite.getInvokeExpr();
					return this.supportsCallee(ie.getMethod());
				}
				return false;
			}

			@Override
			public boolean supportsCallee(SootMethod method) {
				SootClass sootClass = method.getDeclaringClass();
				boolean isInputStream = sootClass.getName().equals(InputStream.class.getName());
				while (!isInputStream && sootClass.hasSuperclass()) {
					sootClass = sootClass.getSuperclass();
					sootClass.getName().equals(InputStream.class.getName());
				}
				return (isInputStream && method	.getName()
								.equals("read"));
			}

			@Override
			public boolean isExclusive(Stmt stmt, Abstraction taintedPath) {
				return false;
			}

			@Override
			public void initialize(InfoflowManager manager) {
				// TODO Auto-generated method stub

			}

			@Override
			public int getWrapperMisses() {
				return 0;
			}

			@Override
			public int getWrapperHits() {
				return 0;
			}

			@Override
			public Set<Abstraction> getTaintsForMethod(Stmt stmt,
					Abstraction d1, Abstraction taintedPath) {
				if (!stmt.containsInvokeExpr()) {
					return null;
				}
				
				Set<Abstraction> result = new HashSet<>();
				final SootMethod method = stmt.getInvokeExpr().getMethod();
				final InvokeExpr ie = stmt.getInvokeExpr();
				if (!taintedPath.getAccessPath().isEmpty()) {
					if (method.getName().equals("read") && ie.getArgCount() >= 1) {
						result.add(d1.deriveNewAbstraction(ie.getArg(0), false, stmt, ie.getArg(0).getType(), ArrayTaintType.ContentsAndLength));
					} else if (ie instanceof InstanceInvokeExpr && method.getName().equals("update")) {
						result.add(d1.deriveNewAbstraction(AccessPathFactory.v().createAccessPath(((InstanceInvokeExpr) ie).getBase(), true), stmt));
					}	
				}
				
				if (result.isEmpty()) {
					return null;
				}
				
				return result;
			}

			@Override
			public Set<Abstraction> getAliasesForMethod(Stmt stmt,
					Abstraction d1, Abstraction taintedPath) {
				return null;
			}
		});

		easyTaintWrapper.setAggressiveMode(false);
		// app.setTaintWrapper(easyTaintWrapper);
		app.setTaintWrapper(taintSet);

		try {
			app.calculateSourcesSinksEntrypoints(this.sourceSinksFilePath.getPath());
		} catch (Exception e) {
		}

		return app;
	}

	public interface FlowResultHandler {
		void onResult(boolean found);
	}
}
