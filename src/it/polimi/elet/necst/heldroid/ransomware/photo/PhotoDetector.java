/**
 * 
 */
package it.polimi.elet.necst.heldroid.ransomware.photo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.ransomware.emulation.ReflectionSimulator;
import it.polimi.elet.necst.heldroid.utils.CFGUtils;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Ref;
import soot.jimple.Stmt;
import soot.jimple.infoflow.cfg.SharedCfg;
import soot.jimple.infoflow.problems.conditions.BreadthFirstSearch;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.util.SystemClassHandler;

/**
 * @author Nicola Dellarocca
 *
 */
public class PhotoDetector {

	protected IInfoflowCFG mCfg;
	protected DecodedPackage mTarget;

	protected String[] relatedMethods = {
			"android.hardware.Camera->takePicture",
			"android.hardware.camera2.CameraManager->openCamera",
			"getNumberOfCameras",
			"getCameraInfo"};

	/**
	 * @param target
	 *            the target to set
	 */
	public void setTarget(DecodedPackage target) {
		this.mTarget = target;
	}

	/**
	 * 
	 * @param reuseCfg
	 * @return
	 * @throws IllegalStateException
	 */
	public Wrapper<PhotoAdminResult> detect(boolean reuseCfg)
			throws IllegalStateException {
		if (mTarget == null)
			throw new IllegalStateException("Target not set");

		createCfg(reuseCfg);

		PhotoAdminResult result = findCameraMethods();

		System.out.println("Overall result: "+result);
		return new Wrapper<>(result);
	}

	protected PhotoAdminResult findCameraMethods() {
		PhotoAdminResult result = new PhotoAdminResult();
		
		BreadthFirstSearch<Unit> searcher = new BreadthFirstSearch<Unit>(mCfg) {

			@Override
			protected Collection<Unit> nextNodes(Unit current) {
				Collection<Unit> result = new HashSet<>(0);
						
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
				if (cfg.isCallStmt(node)) {
					InvokeExpr ie = ((Stmt) node).getInvokeExpr();

					SootMethod sm = ie.getMethod();
					SootClass sc = sm.getDeclaringClass();

					String composed = sc.getName() + "->" + sm.getName();
					for (String s : relatedMethods) {
						if (composed.equals(s)) {
							return false;
//							return true;
						}
					}
				}
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

		for (Unit start : startPoints) {
			if (!searcher.search(start, false).isEmpty()) {
				result.setPhotoDetected(true);
				return result;
			}
		}
		System.out.println("****** HERE");
		// If we reach this point, we found no method

		ArrayList<String> relatedMethods = new ArrayList<>();
		relatedMethods.add("takePicture");
		relatedMethods.add("getNumberOfCameras");
		relatedMethods.add("getCameraInfo");
		RefType enforceTargetType = null;// RefType.v("android.hardware.Camera");
		boolean fromReflection = ReflectionSimulator.searchReflection(mCfg, relatedMethods, enforceTargetType);
		
		result.setPhotoDetected(fromReflection);
		result.setFromReflection(fromReflection);
		return result;
	}

	protected void createCfg(boolean reuseCfg) {
		if (reuseCfg) {
			this.mCfg = SharedCfg.waitForCfg();
		} else {
			this.mCfg = CFGUtils.createCfg(mTarget);
		}
	}

}
