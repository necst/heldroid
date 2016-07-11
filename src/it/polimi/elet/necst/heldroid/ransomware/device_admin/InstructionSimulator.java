/**
 * 
 */
package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import soot.PrimType;
import soot.RefType;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.jimple.DoubleConstant;
import soot.jimple.FloatConstant;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.LongConstant;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.infoflow.problems.conditions.BreadthFirstSearch;
import soot.jimple.infoflow.problems.conditions.ValueUtil;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;

/**
 * This abstract class simulates the execution of instructions on a variable
 * thanks to reflection.
 * 
 * @author Nicola Dellarocca
 *
 * @param <Type>
 *            The type of the {@link Value}.
 */
public class InstructionSimulator
		extends BreadthFirstSearch<InstructionSimulator.Node> {

	protected Unit startNode;
	protected Unit endNode;

	/**
	 * @param cfg
	 */
	public InstructionSimulator(IInfoflowCFG cfg, Unit startNode,
			Unit endNode) {
		super(cfg);

		this.startNode = startNode;
		this.endNode = endNode;
	}

	public static class Node {
		private String value;
		private Unit unit;

		/**
		 * Convenience constructor
		 */
		public Node(String value, Unit node) {
			this.value = value;
			this.unit = node;
		}

		/**
		 * @return the node
		 */
		public Unit getNode() {
			return unit;
		}

		/**
		 * @param node
		 *            the node to set
		 */
		public void setNode(Unit node) {
			this.unit = node;
		}

		/**
		 * @return the value
		 */
		public String getValue() {
			return value;
		}

		/**
		 * @param value
		 *            the value to set
		 */
		public void setValue(String value) {
			this.value = value;
		}
		
		/**
		 * {@inheritDoc}
		 */
		@Override
		public String toString() {
			return unit+"->"+value;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Collection<InstructionSimulator.Node> nextNodes(
			InstructionSimulator.Node current) {
		Set<Node> result = new HashSet<>();

		/*
		 * If this is a method call we need to check the callee. If it is a
		 * String transformation method we will apply it, otherwise we will
		 * inspect successors
		 */
		if (cfg.isCallStmt(current.unit)) {
			Collection<SootMethod> callees = cfg.getCalleesOfCallAt(
					current.unit);

			for (SootMethod callee : callees) {
				/*
				 * If it calls a String transformation method, then apply it
				 */
				if (callee	.getDeclaringClass()
							.getName()
							.equals(current.value	.getClass()
													.getName())) {
					InvokeExpr ie = ((Stmt) current.unit).getInvokeExpr();
					
					// Extract params
					Object[] invokeArgs = new Object[ie.getArgCount()];
					for (int i=0; i<invokeArgs.length; i++) {
						Value arg = ie.getArg(i);
						
						invokeArgs[i] = ValueUtil.extractValue(arg);
					}
					
					// Assign to the node the new value
					current.value = applyTransformation(current.value, callee, invokeArgs);
				} else {
					for (Unit startPoint : cfg.getStartPointsOf(callee)) {
						result.add(new Node(current.value, startPoint));
					}
				}
			}
		}

		// Add all successors
		for (Unit succ : cfg.getSuccsOf(current.unit)) {
			result.add(new Node(current.value, succ));
		}

		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected boolean isResult(InstructionSimulator.Node node) {
		return node.unit.equals(endNode);
	}

	/**
	 * Applies the transformation to the current value and returns the
	 * transformed value.
	 * 
	 * @param currentValue
	 * @param transformation
	 * @return
	 */
	protected String applyTransformation(String currentValue,
			SootMethod transformation, Object[] values) {
		// Ignore constructor
		if (transformation.getName().equals("<init>")) {
			return currentValue;
		}
		
		Class<?> clazz = String.class;

		Class<?>[] paramValues = new Class<?>[transformation.getParameterCount()];

		try {
			for (int i = 0; i < paramValues.length; i++) {
				Type t = transformation.getParameterType(i);

				String className = null;
				if (t instanceof PrimType) {
					className = ((PrimType) t)	.boxedType()
												.getClassName();
				} else if (t instanceof RefType) {
					className = ((RefType) t).getClassName();
				}

				if (className == null) {
					throw new IllegalArgumentException(
							"Cannot detect parameter types for: "
									+ transformation);
				}

				if (className.equals("java.lang.Integer")) {
					paramValues[i] = int.class; 
				} else {
					paramValues[i] = Class.forName(className);
				}

			}
			System.out.println("*** Invoking "+transformation.getName()+" with params: "+Arrays.toString(paramValues)+" on value: "+currentValue);
			Method method = clazz.getDeclaredMethod(transformation.getName(), paramValues);
			Object result = method.invoke(currentValue, values);
			System.out.println("*** -> RESULT = "+result);
			if (result instanceof String) {
				return (String) result;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}