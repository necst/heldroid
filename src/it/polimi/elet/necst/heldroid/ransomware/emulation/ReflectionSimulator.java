/**
 * 
 */
package it.polimi.elet.necst.heldroid.ransomware.emulation;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import it.polimi.elet.necst.heldroid.ransomware.device_admin.InstructionSimulator;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.InstructionSimulator.Node;
import soot.Immediate;
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
import soot.jimple.infoflow.problems.conditions.BreadthFirstSearch;
import soot.jimple.infoflow.problems.conditions.ConstantDeclarationFinder;
import soot.jimple.infoflow.problems.conditions.DeclarationFinder;
import soot.jimple.infoflow.problems.conditions.SootClassUtil;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

/**
 * @author Nicola Dellarocca
 *
 */
public class ReflectionSimulator {

	public static boolean searchReflection(IInfoflowCFG cfg, ArrayList<String> relatedMethods,
			final RefType enforceTargetType) {
		if (relatedMethods == null || relatedMethods.isEmpty()) {
			throw new IllegalArgumentException(
					"You must provide at least one related method");
		}

		BreadthFirstSearch<Unit> searcher = new BreadthFirstSearch<Unit>(cfg) {

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
						System.out.println("********** CALLEEE: "+callee);
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
			startPoints.addAll(cfg.getStartPointsOf(entryPoint));
		}

		// For each entry point let's perform a search
		Set<Unit> results = new HashSet<>(0);
		for (Unit start : startPoints) {
			results.addAll(searcher.search(start, false));
		}
		
		System.out.println("****** Start points: "+results.size());

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
			DeclarationFinder finder = new DeclarationFinder(cfg,
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
			Set<String> names = findHardcodedMethodName(cfg, methodSearched,
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
						(enforceTargetType != null ? (enforceTargetType.getClassName() + "->") : "") + name)) {
					System.out.println("*** YAY");
					return true;
				}
			}

			System.out.println("NAY");
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	private static Set<String> findHardcodedMethodName(IInfoflowCFG cfg,
			Set<Unit> reflectionMethodInvokes,
			ArrayList<String> methodsToFind) {

		for (Unit reflectionMethodInvoke : reflectionMethodInvokes) {
			if (reflectionMethodInvoke instanceof AssignStmt
					&& cfg.isCallStmt(reflectionMethodInvoke)) {
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
				
				System.out.println("Is string constant??? "+ ie +" -> "+(ie.getArg(0) instanceof StringConstant));
				if (ie.getArg(0) instanceof StringConstant) {
					Set<String> result = new HashSet<>();
					result.add(((StringConstant) (ie.getArg(0))).value);
					return result;
				}

				// Find method name
				// findMethodNameReflection(iie.getBase(), callStmt);
				ConstantDeclarationFinder finder = new ConstantDeclarationFinder(
						cfg, ie.getArg(0));
				Set<Unit> constantDeclarations = finder.search(assignStmt,
						true);

				System.out.println(
						"*** Constant decL = " + constantDeclarations);

				Set<String> extractedHardcodedNames = new HashSet<>(0);
				for (Unit constantDeclaration : constantDeclarations) {
					if (constantDeclaration instanceof AssignStmt) {
						AssignStmt assign = (AssignStmt) constantDeclaration;

						Value methodName = assign.getRightOp();

						String extractedString = extractString(cfg, methodName,
								constantDeclaration);

						InstructionSimulator simulator = new InstructionSimulator(
								cfg, constantDeclaration,
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
										cfg, constantDeclaration,
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
	
	private static String extractString(IInfoflowCFG cfg, Value value, Unit usageNode) {
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
					cfg, value);
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
}
