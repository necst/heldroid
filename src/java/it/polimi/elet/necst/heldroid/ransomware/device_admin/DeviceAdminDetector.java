package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.APPLICATION_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.BIND_DEVICE_ADMIN_VALUE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.DEVICE_ADMIN_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.DEVICE_ADMIN_VALUE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.META_DATA_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.NAME_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.PERMISSION_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RECEIVER_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RESOURCE_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RESOURCE_REGEX;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_PERMISSION_SDK_23_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_PERMISSION_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_POLICIES_TAG;

import java.io.File;
import java.io.FilenameFilter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult.Policy;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.InstructionSimulator.Node;
import it.polimi.elet.necst.heldroid.ransomware.encryption.EncryptionFlowDetector;
import it.polimi.elet.necst.heldroid.utils.CFGUtils;
import it.polimi.elet.necst.heldroid.utils.FileSystem;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;

import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.infoflow.cfg.SharedCfg;
import soot.jimple.infoflow.problems.conditions.BreadthFirstSearch;
import soot.jimple.infoflow.problems.conditions.ConstantDeclarationFinder;
import soot.jimple.infoflow.problems.conditions.DeclarationFinder;
import soot.jimple.infoflow.problems.conditions.SootClassUtil;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

/**
 * This class analyzes an APK file in order to discover if the app uses Android
 * Device Administrator API.
 * 
 * @author Nicola Dellarocca
 *
 */
public class DeviceAdminDetector {
	/*
	 ***********************************************
	 * Please note the static import for constants *
	 ***********************************************
	 */

	// Resource files are like: @type/file_name
	private static final Pattern POLICIES_FILE_REGEX = Pattern.compile(
			RESOURCE_REGEX);

	private DecodedPackage mTarget;
	private DocumentBuilderFactory mDbFactory;
	private DocumentBuilder mDb;

	private IInfoflowCFG mCfg;

	/**
	 * Creates a {@code DeviceAdminDetector} instance
	 * 
	 * @throws ParserConfigurationException
	 *             if it is not possible to create an XML parser for the
	 *             AndroidManifest.xml file.
	 */
	public DeviceAdminDetector() throws ParserConfigurationException {
		this.mDbFactory = DocumentBuilderFactory.newInstance();
		this.mDb = mDbFactory.newDocumentBuilder();
	}

	/**
	 * Scans the AndroidManifest.xml file to discover if the app uses the
	 * {@link Constants#BIND_DEVICE_ADMIN_VALUE} permission.
	 * 
	 * @param manifest
	 *            The manifest in which the permission will be searched.
	 * @return <code>true</code> if the manifest contains such permission,
	 *         <code>false</code> otherwise.
	 */
	private boolean findDeviceAdminPermission(Document manifest) {
		Element root = manifest.getDocumentElement();

		// First search inside <uses-permission> tags
		Collection<Element> usesPermissionTags = Xml.getElementsByTagName(root,
				USES_PERMISSION_TAG);
		for (Element usesPermissionTag : usesPermissionTags) {
			if (usesPermissionTag.hasAttribute(NAME_ATTRIBUTE)
					&& usesPermissionTag.getAttribute(NAME_ATTRIBUTE)
										.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}
		}

		// GC
		usesPermissionTags = null;

		// Now look inside <uses-permission-sdk-23> tags
		Collection<Element> usesPermission23Tags = Xml.getElementsByTagName(
				root, USES_PERMISSION_SDK_23_TAG);
		for (Element usesPermission23Tag : usesPermission23Tags) {
			if (usesPermission23Tag.hasAttribute(NAME_ATTRIBUTE)
					&& usesPermission23Tag	.getAttribute(NAME_ATTRIBUTE)
											.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}
		}
		usesPermission23Tags = null;

		// Now look inside the <application> tag
		Element application = Xml.getChildElement(root, APPLICATION_TAG);
		if (application.hasAttribute(PERMISSION_ATTRIBUTE)
				&& application	.getAttribute(PERMISSION_ATTRIBUTE)
								.equals(BIND_DEVICE_ADMIN_VALUE)) {
			return true;
		}
		application = null;

		// Then look inside <receiver> tag
		Collection<Element> receivers = Xml.getElementsByTagName(root,
				RECEIVER_TAG);
		for (Element receiver : receivers) {
			if (receiver.hasAttribute(PERMISSION_ATTRIBUTE)
					&& receiver	.getAttribute(PERMISSION_ATTRIBUTE)
								.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}

			// Also look inside <meta-data> for such permission
			Element metadata = Xml.getChildElement(receiver, META_DATA_TAG);
			if (metadata != null) {
				if (metadata.hasAttribute(PERMISSION_ATTRIBUTE)
						&& metadata	.getAttribute(PERMISSION_ATTRIBUTE)
									.equals(BIND_DEVICE_ADMIN_VALUE)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Scans the Android Manifest to (possibly) find the resource containing
	 * Device Administrator policies.
	 * 
	 * @return The string identifying an Android resource (in the form
	 *         {@code @<type>/<file_name>} or {@code null}, if the Manifest does
	 *         not contain such reference.
	 */
	private String findDeviceAdminPoliciesFile() {
		try {
			Document document = mDb.parse(mTarget.getAndroidManifest());
			Element root = document.getDocumentElement();

			Collection<Element> receivers = Xml.getElementsByTagName(root,
					RECEIVER_TAG);

			boolean hasDeviceAdminPermission = findDeviceAdminPermission(
					document);
			if (!hasDeviceAdminPermission) {
				return null;
			}

			/*
			 * At this point the manifest contains such permission. We need to
			 * find the receiver that contains the appropriate <meta-data> child
			 * (i.e. that contains the device admin policies file reference)
			 */
			for (Element receiver : receivers) {
				// Get <meta-data> child
				Element metadata = Xml.getChildElement(receiver, META_DATA_TAG);
				if (metadata != null) {
					if (metadata.hasAttribute(NAME_ATTRIBUTE)
							&& metadata	.getAttribute(NAME_ATTRIBUTE)
										.equals(DEVICE_ADMIN_VALUE)) {

						if (metadata.hasAttribute(RESOURCE_ATTRIBUTE)) {
							return metadata.getAttribute(RESOURCE_ATTRIBUTE);
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Exception: " + e);
		}
		return null;
	}

	/**
	 * Parses {@code policiesFile} trying to extract all (known) policies.
	 * 
	 * See {@link DeviceAdminResult.Policy} for the list of currently supported
	 * policies.
	 * 
	 * @param policiesFile
	 * @return A wrapper for {@link DeviceAdminResult} object. The wrapper will
	 *         never be {@code null}.
	 */
	private Wrapper<DeviceAdminResult> parseDeviceAdminPoliciesFile(
			File policiesFile) {

		// Holds the result
		DeviceAdminResult result = null;

		// Perform checks only if policies file exists
		if (policiesFile.exists()) {
			try {
				Document document = mDb.parse(policiesFile);
				Element root = document.getDocumentElement();

				// It must start wit <device-admin> tag
				if (root.getTagName()
						.equals(DEVICE_ADMIN_TAG)) {
					// This app makes use of <device-admin>
					result = new DeviceAdminResult();
					result.setDeviceAdminUsed(true);

					// This tag's child are the policies
					Element usesPolicies = Xml.getChildElement(root,
							USES_POLICIES_TAG);
					if (usesPolicies != null) {

						// Will contain a list of policies
						List<Element> policies = Xml.getChildElements(
								usesPolicies);
						if (policies.size() > 0) {
							// Add all policies to result
							for (Element policy : policies) {
								// Try to parse policies, otherwise skip them
								try {
									Policy p = Policy.parseString(
											policy.getTagName());
									result.addPolicy(p);
								} catch (Exception e) {
									System.err.println(
											"Skipping unknown policy: "
													+ policy);
								}
							}
						}

					}
				}

			} catch (Exception e) {
				System.err.println("Exception: " + e);
				return new Wrapper<DeviceAdminResult>(null);
			}
		}

		return new Wrapper<DeviceAdminResult>(result);
	}

	/**
	 * Creates the CFG. If reuseCfg is set to <code>true</code>, it will reuse
	 * the CFG created by someone else, otherwise it will create a brand new
	 * one.
	 * 
	 * Please note that this class will wait until someone else creates the CFG,
	 * so <b>it might wait forever if no one creates the CFG</b>.
	 * 
	 * @param reuseCfg
	 *            If <code>true</code> it will wait until someone else creates
	 *            the CFG, otherwise it will create a new CFG by itself.
	 */
	private void createCfg(boolean reuseCfg) {
		if (reuseCfg) {
			mCfg = SharedCfg.waitForCfg();
		} else {
			mCfg = CFGUtils.createCfg(mTarget);
			// /*
			// * We will generate the CFG using the latest android version
			// * available on the platform.
			// */
			// File libPath = Globals.getLatestAndroidVersion();
			// if (libPath == null)
			// libPath = Globals.ANDROID_PLATFORMS_DIRECTORY;
			//
			// // A new setup application is required to create the CFG
			// SetupApplication app = new SetupApplication(
			// libPath.getAbsolutePath(), mTarget .getOriginalApk()
			// .getAbsolutePath());
			//
			// app.getConfig().setIgnoreFlowsInSystemPackages(false);
			// try {
			// app.calculateSourcesSinksEntrypoints("SourcesAndSinks.txt");
			//
			// // Configure Soot
			// soot.G.reset();
			//
			// Options .v()
			// .set_src_prec(Options.src_prec_apk);
			// Options .v()
			// .set_process_dir(Collections.singletonList(
			// mTarget .getOriginalApk()
			// .getAbsolutePath()));
			// Options .v()
			// .set_force_android_jar(libPath.getAbsolutePath());
			// Options .v()
			// .set_whole_program(true);
			// Options .v()
			// .set_allow_phantom_refs(true);
			// Options .v()
			// .set_output_format(Options.output_format_jimple);
			// Options .v()
			// .setPhaseOption("cg.spark", "on");
			//
			// Scene .v()
			// .loadNecessaryClasses();
			//
			// SootMethod dummyMain = app .getEntryPointCreator()
			// .createDummyMain();
			// // The dummy main is the starting point
			// Options .v()
			// .set_main_class(dummyMain.getSignature());
			//
			// // Share the dummy main
			// Scene .v()
			// .setEntryPoints(Collections.singletonList(dummyMain));
			//
			// System.out.println(dummyMain.getActiveBody());
			//
			// PackManager .v()
			// .runPacks();
			//
			// DefaultBiDiICFGFactory factory = new DefaultBiDiICFGFactory();
			// mCfg = factory.buildBiDirICFG(CallgraphAlgorithm.OnDemand,
			// false);
			//
			// System.out.println(dummyMain.getActiveBody());
			// // List<SootMethod> entryPoints = Scene.v().getEntryPoints();
			//// printCfg(entryPoints.get(0));
			// } catch (Exception e) {
			// e.printStackTrace();
			// }

		}

	}

	/**
	 * Prints all CFG nodes in stdout in a breadth-first way.
	 * 
	 * @param startPoint
	 *            The node from which to start the CFG exploration.
	 */
	private void printCfg(SootMethod startPoint) {
		Deque<Unit> stack = new LinkedList<>();
		HashSet<Unit> visited = new HashSet<>();
		stack.addAll(mCfg.getStartPointsOf(startPoint));

		while (!stack.isEmpty()) {
			Unit node = stack.pop();

			if (visited.contains(node))
				continue;

			visited.add(node);
			System.out.println(node);
			System.out.println("*** " + mCfg.getSuccsOf(node));
			stack.addAll(mCfg.getSuccsOf(node));

			if (mCfg.isCallStmt(node)) {
				Collection<SootMethod> callees = mCfg.getCalleesOfCallAt(node);
				for (SootMethod callee : callees) {
					stack.addAll(mCfg.getStartPointsOf(callee));
				}
			}
		}

	}

	/**
	 * Scans the APK trying to discover if the app makes use of Android Device
	 * Administrator API.
	 * 
	 * @param reuseCfg
	 *            Whether the detector should reuse the CFG that has been
	 *            generated by someone else (e.g. the
	 *            {@link EncryptionFlowDetector}).
	 * 
	 * @return a wrapper containing a {@link DeviceAdminResult} object. The
	 *         wrapper will never be {@code null}. If the app does not use the
	 *         Device Administrator API, the result will be a wrapper for a
	 *         {@code null} object (i.e. {@code wrapper.value} will be
	 *         {@code null}.
	 * @throws IllegalStateException
	 *             if a {@link #setTarget(DecodedPackage) target} is not set or
	 *             the CFG cannot be built
	 */
	public Wrapper<DeviceAdminResult> detect(boolean reuseCfg)
			throws IllegalStateException {
		if (mTarget == null) {
			throw new IllegalStateException("Target is not set");
		}

		// First of all create the CFG. It will be used later
		createCfg(reuseCfg);

		if (this.mCfg == null)
			throw new IllegalStateException("Cannot create the CFG");

		String deviceAdminPoliciesFile = findDeviceAdminPoliciesFile();

		/*
		 * If no device admin policies file is found, we have nothing to do
		 */
		if (deviceAdminPoliciesFile != null) {
			Matcher matcher = POLICIES_FILE_REGEX.matcher(
					deviceAdminPoliciesFile);
			if (matcher.matches()) {
				// This file should always be in XML folder
				File targetDirectory = new File(mTarget.getResourcesDirectory(),
						"xml");
				if (targetDirectory.exists() && targetDirectory.isDirectory()) {

					// Get the name of the policies file, if it exists
					final String fileName = matcher.group("name");

					if (fileName != null && fileName.length() > 0) {
						/*
						 * If such file exists, let's search it in /res
						 * subfolders
						 */
						FilenameFilter filter = new FilenameFilter() {
							/*
							 * Some files have no extension, so let's check both
							 * with and without .xml extension
							 */
							@Override
							public boolean accept(File dir, String name) {
								// Some APKs do not add the .xml extension
								String regex = "^" + fileName + "(\\.\\w+)?$";
								return name.matches(regex);
							}
						};

						// Search it
						List<File> matchingFiles = FileSystem.listFilesRecursively(
								mTarget.getResourcesDirectory(), filter);

						/*
						 * Should never happen, since a device admin policies
						 * file is specified in the AndroidManifest
						 */
						if (matchingFiles.size() == 0) {
							System.err.println(
									"Error: policies file not found in res subfolders");
							return new Wrapper<DeviceAdminResult>(null);
						}

						// File policiesFile = new File(xmlDirectory, fileName);
						File policiesFile = matchingFiles.get(0);

						Wrapper<DeviceAdminResult> result = parseDeviceAdminPoliciesFile(
								policiesFile);

						// It should never be null, since we've just created it!
						if (result != null && result.value != null
								&& result.value.getPolicies() != null) {

							// Loop over supported policies only
							for (Policy policy : Policy.getSupportedPolicies()) {
								/*
								 * If policy is not present in policies file,
								 * don't waste time
								 */
								if (!result.value	.getPolicies()
													.contains(policy)) {
									continue;
								}

								/*
								 * Check if the policy is actually used in the
								 * code
								 */
								PolicyUsage usage = isPolicyUsed(policy);

								/*
								 * If it is not used, remove it from the list of
								 * used policies
								 */
								if (usage == PolicyUsage.NONE) {
									System.out.printf(
											"Policy %S is not used. Removing it...\n",
											policy.name());
									result.value.getPolicies()
												.remove(policy);
								} else {
									System.out.printf("Policy %S is used!!\n",
											policy.name());
									// Update result accordingly to usage type
									if (usage == PolicyUsage.REFLECTION) {
										result.value.setFromReflection(true);
									}
								}
							}
						}

						return result;
					}
				}
			}
		}
		// If we reach this point it means that no policy is found
		return new Wrapper<DeviceAdminResult>(null);
	}

	// /**
	// * Checks if the {@code policy} is actually used inside the smali code.
	// This
	// * check is performed by looking for dangerous method calls inside any of
	// * the smali files of the app referenced by the {@code target} instance
	// * variable.
	// *
	// * Please note that the currently supported policies are only
	// * {@link Policy#USES_POLICY_WIPE_DATA} and
	// * {@link Policy#USES_POLICY_RESET_PASSWORD}.
	// *
	// * @param policy
	// * The policy to test
	// * @return {@code true} if the code contains such method calls,
	// * {@code false} otherwise.
	// */
	// private boolean isPolicyUsed(Policy policy) {
	// if (policy == null) {
	// throw new IllegalArgumentException(
	// "You must provide a valid policy");
	// }
	//
	// String regex = null;
	//
	// switch (policy) {
	// case USES_POLICY_WIPE_DATA:
	// // Look for methods: DevicePolicyManager.wipeData(int)
	// regex =
	// "^.*Landroid/app/admin/DevicePolicyManager;->wipeData\\(I\\)V.*$";
	// break;
	//
	// case USES_POLICY_RESET_PASSWORD:
	// // Look for methods: DevicePolicyManager.resetPassword(String, int)
	// regex =
	// "^.*Landroid/app/admin/DevicePolicyManager;->resetPassword\\(Ljava/lang/String;I\\)Z.*$";
	// break;
	//
	// default:
	// throw new IllegalArgumentException(
	// "This policy is not supported yet.");
	// }
	//
	// File smaliDirectory = mTarget.getSmaliDirectory();
	//
	// return FileSystem.searchRecursively(smaliDirectory, regex);
	// }
	
	private enum PolicyUsage {
		NONE,
		METHOD_CALL,
		REFLECTION
	}

	/**
	 * Searches if the policy is used (directly or through reflection).
	 * 
	 * @param policy
	 *            The policy to check.
	 * @return <code>true</code> if the policy is used, <code>false</code>
	 *         otherwise.
	 * 
	 */
	private PolicyUsage isPolicyUsed(final Policy policy) {
		if (policy == null) {
			throw new IllegalArgumentException(
					"You must provide a valid policy");
		}

		if (!policy.isSupported()) {
			throw new IllegalArgumentException(
					"This policy is not supported yet");
		}

		if (this.mCfg == null) {
			throw new IllegalStateException("CFG is null");
		}

		/*
		 * Search if one of the methods related to the policy is call either
		 * directly or through reflection.
		 */
		if (searchRelatedMethod(policy)) {
			return PolicyUsage.METHOD_CALL;
		}

		/*
		 * Otherwise search for reflection usage
		 */
		if (searchReflection(policy.getRelatedMethods(),
				RefType.v("android.app.admin.DevicePolicyManager"))) {
			return PolicyUsage.REFLECTION;
		}
		
		return PolicyUsage.NONE;
	}

	/**
	 * Searches for methods invocation through reflection and return a boolean
	 * indicating if they have been found.
	 * 
	 * @param relatedMethods
	 *            The collection of methods we are interested in (i.e. of which
	 *            we want to discover invocations). It must contain at least 1
	 *            element.
	 * @param enforceTargetType
	 *            The type of the target object (i.e. the type of object on
	 *            which the method will be invoked). It can be <code>null</code>
	 *            if you don't care about its type.
	 * @return <code>true</code> if any reflection method invocations is found,
	 *         otherwise <code>false</code>.
	 */
	private boolean searchReflection(ArrayList<String> relatedMethods,
			final RefType enforceTargetType) {
		if (relatedMethods == null || relatedMethods.isEmpty()) {
			throw new IllegalArgumentException(
					"You must provide at least one related method");
		}

		BreadthFirstSearch<Unit> searcher = new BreadthFirstSearch<Unit>(mCfg) {

			@Override
			protected Collection<Unit> nextNodes(Unit current) {
				Collection<Unit> result = new HashSet<>(0);

				// Add successors
				result.addAll(cfg.getSuccsOf(current));

				// If this is a method call, add callee's start points
				if (cfg.isCallStmt(current)) {
					Collection<SootMethod> callees = cfg.getCalleesOfCallAt(
							current);
					for (SootMethod callee : callees) {
						result.addAll(cfg.getStartPointsOf(callee));
					}
				}

				return result;
			}

			@Override
			protected boolean isResult(Unit node) {
				/*
				 * If it's not a method call then it is not a valid result.
				 */
				if (cfg.isCallStmt(node)) {
					Collection<SootMethod> callees = cfg.getCalleesOfCallAt(
							node);

					/*
					 * Obtain the InvokeExpression to get details of method
					 * invocation.
					 */
					InvokeExpr ie = ((Stmt) node).getInvokeExpr();

					/*
					 * This method must have exactly 2 args, otherwise it is the
					 * wrong method. The args are: 1: Target object 2: Array of
					 * arguments
					 */
					if (ie.getArgCount() != 2) {
						return false;
					}

					/*
					 * Usually there's only 1 callee, but IInfoflowCFG returns a
					 * collection...
					 */
					for (SootMethod callee : callees) {
						// Get the invoked method's class
						SootClass declClass = callee.getDeclaringClass();

						// Check the target's type
						if (enforceTargetType != null
								&& !enforceTargetType.equals(ie	.getArg(0)
																.getType())) {
							return false;
						}

						/*
						 * Check that the invoked method is
						 * java.lang.reflect.Method->invoke
						 */
						if (callee	.getName()
									.equals("invoke")
								&& SootClassUtil.isOrExtendsClass(declClass,
										Method.class)) {
							return true;
						}
					}
				}

				// If we reach this point it means that no method is found.
				return false;
			}
		};

		// Get dummy main entry points
		List<SootMethod> entryPoints = Scene.v()
											.getEntryPoints();
		List<Unit> startPoints = new ArrayList<>();

		for (SootMethod entryPoint : entryPoints) {
			startPoints.addAll(mCfg.getStartPointsOf(entryPoint));
		}

		// For each entry point let's perform a search
		Set<Unit> results = new HashSet<>(0);
		for (Unit start : startPoints) {
			results.addAll(searcher.search(start, false));
		}

		/*
		 * If there is at least 1 result search for relatedMethods, otherwise
		 * return null;
		 */
		if (results.isEmpty()) {
			return false;
		}

		/*
		 * Find the declaration (i.e. variable assignment) for the method that
		 * is invoked through reflection. In other words we want to find an
		 * instruction like:
		 * 
		 * java.lang.Method object = <whatever>
		 */
		Set<Unit> methodSearched = null;
		for (Unit methodInvocation : results) {
			Value reflectionMethodLocal = ((InstanceInvokeExpr) ((Stmt) methodInvocation).getInvokeExpr()).getBase();
			DeclarationFinder finder = new DeclarationFinder(mCfg,
					reflectionMethodLocal);

			methodSearched = finder.search(methodInvocation, true);
		}

		/*
		 * The assignment must exist somewhere in the code. Check if we were
		 * able to find it
		 */
		if (methodSearched == null || methodSearched.isEmpty()) {
			return false;
		}

		/*
		 * Here we want to check if the method invoked through reflection is one
		 * of the relatedMethods.
		 */
		try {
			/*
			 * The set of names of those methods that are invoked through
			 * reflection
			 */
			Set<String> names = findHardcodedMethodName(methodSearched,
					relatedMethods);

			System.out.println("*** Related methods = " + relatedMethods);
			System.out.println("*** HarcodedMethodNames = " + names);

			// Check if at least one related method is contained inside the set
			// for (String relatedMethod : relatedMethods) {
			// if (names.contains(relatedMethod))
			// return true;
			// }

			for (String name : names) {
				if (relatedMethods.contains(
						enforceTargetType.getClassName() + "->" + name)) {
					return true;
				}
			}

			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * Navigates the CFG backwards looking for hardcoded strings related to
	 * methods invoked through reflection.
	 * 
	 * @param reflectionMethodInvokes
	 * @param methodsToFind
	 *            The array of methods to find. It must contain at least one
	 *            element. The format of the string should be the following:
	 * 
	 *            <pre>
	 *            {@code <declaring_class>-><method_name>(<params_type>)}
	 * 			</pre>
	 * 
	 *            for instance:
	 * 
	 *            <pre>
	 *            {@code java.lang.String->substring(int,int)}
	 * 			</pre>
	 * 
	 * @return
	 */
	private Set<String> findHardcodedMethodName(
			Set<Unit> reflectionMethodInvokes,
			ArrayList<String> methodsToFind) {

		for (Unit reflectionMethodInvoke : reflectionMethodInvokes) {
			if (reflectionMethodInvoke instanceof AssignStmt
					&& mCfg.isCallStmt(reflectionMethodInvoke)) {
				AssignStmt assignStmt = (AssignStmt) reflectionMethodInvoke;
				InvokeExpr ie = assignStmt.getInvokeExpr();

				System.out.println(
						"****** " + assignStmt + " -> " + ie.getArg(0)
															.getType());
				// Ensure that the first parameter is of type String
				if (!ie	.getArg(0)
						.getType()
						.equals(RefType.v("java.lang.String"))) {
					return null;
				}

				// Find method name
				// findMethodNameReflection(iie.getBase(), callStmt);
				ConstantDeclarationFinder finder = new ConstantDeclarationFinder(
						mCfg, ie.getArg(0));
				Set<Unit> constantDeclarations = finder.search(assignStmt,
						true);

				System.out.println(
						"*** Constant decL = " + constantDeclarations);

				Set<String> extractedHardcodedNames = new HashSet<>(0);
				for (Unit constantDeclaration : constantDeclarations) {
					if (constantDeclaration instanceof AssignStmt) {
						AssignStmt assign = (AssignStmt) constantDeclaration;

						Value methodName = assign.getRightOp();

						String extractedString = extractString(methodName,
								constantDeclaration);

						InstructionSimulator simulator = new InstructionSimulator(
								mCfg, constantDeclaration,
								reflectionMethodInvoke);
						Set<InstructionSimulator.Node> nodes = simulator.search(
								new InstructionSimulator.Node(extractedString,
										constantDeclaration),
								true);

						for (Node n : nodes) {
							extractedHardcodedNames.add(n.getValue());
						}
						return extractedHardcodedNames;
					} else if (constantDeclaration instanceof InvokeStmt) {
						InvokeExpr ie2 = ((InvokeStmt) constantDeclaration).getInvokeExpr();
						for (int i = 0; i < ie2.getArgCount(); i++) {
							Value argument = ie2.getArg(i);
							if (argument instanceof StringConstant) {
								InstructionSimulator simulator = new InstructionSimulator(
										mCfg, constantDeclaration,
										reflectionMethodInvoke);
								Set<Node> nodes = simulator.search(
										new InstructionSimulator.Node(
												((StringConstant) argument).value,
												constantDeclaration),
										true);
								for (Node n : nodes)
									extractedHardcodedNames.add(n.getValue());
								return extractedHardcodedNames;
							}
						}
					} else {
						throw new Error("Cannot retrieve hardcoded value");
					}

					return extractedHardcodedNames;
				}

			}
		}
		return null;
	}

	/**
	 * Extracts the string from a value (a {@link StringConstant} or a variable
	 * that can be resolved to a String), if possible.
	 * 
	 * @param value
	 *            The value from which the string should be extracted.
	 * @param usageNode
	 *            The node in which the provided value is used (i.e. the
	 *            starting point for a backwards analysis).
	 * @return The extracted string, if possible, otherwise <code>null</code>.
	 */
	private String extractString(Value value, Unit usageNode) {
		if (value instanceof StringConstant) {
			return ((StringConstant) value).value;
		}

		if (value	.getType()
					.equals(RefType.v("java.lang.String"))) {
			/*
			 * Here we should look for the string definition and, if there is
			 * any transformation to the string (e.g. "replace" or
			 * "replaceAll"), apply it to get the final String.
			 * 
			 * Finally we should return it, if we can find it, otherwise return
			 * null.
			 */
			ConstantDeclarationFinder finder = new ConstantDeclarationFinder(
					mCfg, value);
			Set<Unit> declarations = finder.search(usageNode, true);

			if (declarations.isEmpty()) {
				/*
				 * We didn't succeed in finding the declaration. Return null.
				 */
				return null;
			}

			for (Unit declaration : declarations) {
				/*
				 * It is safe, since ConstantDeclarationFinder returns only
				 * AssignStmts
				 */
				AssignStmt assign = (AssignStmt) declaration;
				/*
				 * It is safe, since ConstantDeclarationFinder returns only
				 * assignment of constants
				 */
				Constant rightOp = (Constant) assign.getRightOp();

				/*
				 * If the constant is a string, simulate its possible
				 * transformations
				 */
				if (rightOp instanceof StringConstant) {
					String raw = ((StringConstant) rightOp).value;
					// simulateTransformations(raw, declaration, usageNode);
				}

				// Otherwise return null
				return null;
			}
		}

		System.out.println("Cannot extract type: " + value.getType());

		return null;
	}

	private boolean searchRelatedMethod(final Policy policy) {
		// We will perform a BFS looking for methods related to the policy.
		BreadthFirstSearch<Unit> searcher = new BreadthFirstSearch<Unit>(mCfg) {

			@Override
			protected Collection<Unit> nextNodes(Unit current) {
				Collection<Unit> result = new ArrayList<>();

				// Skip system classes
				// if
				// (SystemClassHandler.isClassInSystemPackage(cfg.getMethodOf(current).getDeclaringClass().getName()))
				// return new ArrayList<>(0);

				// Add successors
				result.addAll(this.cfg.getSuccsOf(current));

				// Add all called methods, if they exists
				if (this.cfg.isCallStmt(current)) {
					Collection<SootMethod> callees = this.cfg.getCalleesOfCallAt(
							current);
					for (SootMethod callee : callees) {
						result.addAll(this.cfg.getStartPointsOf(callee));
					}
				}
				return result;
			}

			@Override
			protected boolean isResult(Unit node) {
				boolean result = false;
				if (node instanceof Stmt && ((Stmt) node).containsInvokeExpr())
					result = isRelatedUnit(node, policy);

				return result;
			}

		};

		// Get dummy main entry points
		List<SootMethod> entryPoints = Scene.v()
											.getEntryPoints();
		List<Unit> startPoints = new ArrayList<>();

		for (SootMethod entryPoint : entryPoints) {
			startPoints.addAll(mCfg.getStartPointsOf(entryPoint));
		}

		Set<Unit> results = new HashSet<>(0);
		for (Unit start : startPoints) {
			results.addAll(searcher.search(start, false));
		}

		return results.size() > 0;
	}

	/**
	 * Sets the APK file to scan.
	 * 
	 * @param target
	 *            The target for the APK to scan.
	 */
	public void setTarget(DecodedPackage target) {
		this.mTarget = target;
	}

	/**
	 * Checks whether an {@link InvokeExpr} contains a call to a method that is
	 * related to the specified {@link Policy}.
	 * 
	 * @param node
	 *            The node containing a method call.
	 * @param policy
	 *            The policy to check.
	 * @return <code>true</code> if the method call is related to the policy,
	 *         <code>false</code> otherwise.
	 */
	protected boolean isRelatedUnit(Unit node, final Policy policy) {
		if (mCfg.isCallStmt(node)) {
			Collection<SootMethod> calledMethods = mCfg.getCalleesOfCallAt(
					node);

			for (SootMethod calledMethod : calledMethods) {
				if (policy.isMethodRelated(calledMethod))
					return true;
			}
		}

		return false;
	}
}
