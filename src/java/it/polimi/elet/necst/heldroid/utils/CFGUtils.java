/**
 * 
 */
package it.polimi.elet.necst.heldroid.utils;

import java.io.File;
import java.util.Collections;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.ransomware.Globals;
import soot.PackManager;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.cfg.DefaultBiDiICFGFactory;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.options.Options;

/**
 * @author Nicola Dellarocca
 *
 */
public class CFGUtils {

	/**
	 * Creates the CFG associated to the APK referenced by target
	 * 
	 * @param target
	 *            The decoded APK container
	 * @return The CFG or <code>null</code> if some error occurred
	 * 
	 * @throws IllegalArgumentException
	 *             If target is <code>null</code>
	 */
	public static IInfoflowCFG createCfg(DecodedPackage target)
			throws IllegalArgumentException {
		if (target == null)
			throw new IllegalArgumentException("You must provide a valid APK target");
		
		/*
		 * We will generate the CFG using the latest android version available
		 * on the platform.
		 */
		File libPath = Globals.getLatestAndroidVersion();
		if (libPath == null)
			libPath = Globals.ANDROID_PLATFORMS_DIRECTORY;

		// A new setup application is required to create the CFG
		SetupApplication app = new SetupApplication(libPath.getAbsolutePath(),
				target	.getOriginalApk()
						.getAbsolutePath());

		app	.getConfig()
			.setIgnoreFlowsInSystemPackages(false);
		try {
			app.calculateSourcesSinksEntrypoints("SourcesAndSinks.txt");

			// Configure Soot
			soot.G.reset();

			Options	.v()
					.set_src_prec(Options.src_prec_apk);
			Options	.v()
					.set_process_dir(
							Collections.singletonList(target.getOriginalApk()
															.getAbsolutePath()));
			Options	.v()
					.set_force_android_jar(libPath.getAbsolutePath());
			Options	.v()
					.set_whole_program(true);
			Options	.v()
					.set_allow_phantom_refs(true);
			Options	.v()
					.set_output_format(Options.output_format_jimple);
			Options	.v()
					.setPhaseOption("cg.spark", "on");

			Scene	.v()
					.loadNecessaryClasses();

			SootMethod dummyMain = app	.getEntryPointCreator()
										.createDummyMain();
			// The dummy main is the starting point
			Options	.v()
					.set_main_class(dummyMain.getSignature());

			// Share the dummy main
			Scene	.v()
					.setEntryPoints(Collections.singletonList(dummyMain));

			System.out.println(dummyMain.getActiveBody());

			PackManager	.v()
						.runPacks();

			DefaultBiDiICFGFactory factory = new DefaultBiDiICFGFactory();
			IInfoflowCFG cfg = factory.buildBiDirICFG(
					CallgraphAlgorithm.OnDemand, false);

			return cfg;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
}
