/**
 * 
 */
package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import soot.SootMethod;
import soot.Unit;
import soot.Value;
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
public class InstructionSimulator<Type>{

	protected IInfoflowCFG mCfg;
	protected Type mRaw;
	protected Unit mStartPoint;
	protected Unit mEndPoint;

	/**
	 * Holds the current Unit together with the current value for the variable,
	 * since the variable can have different values depending on the execution
	 * path.
	 * 
	 * @author Nicola Dellarocca
	 *
	 */
	private class Node {
		private Type value;
		private Unit unit;

		/**
		 * Convenience constructor
		 */
		private Node(Type value, Unit node) {
			this.value = value;
			this.unit = node;
		}
	}

	/**
	 * Creates a new simulator.
	 * 
	 * @param raw
	 *            The initial value for the variable.
	 * @param startPoint
	 *            The node from which to start the simulation.
	 * @param endPoint
	 *            The node at which the simulation must end.
	 */
	public InstructionSimulator(IInfoflowCFG cfg, Type raw, Unit startPoint,
			Unit endPoint) {
		this.mCfg = cfg;
		this.mRaw = raw;
		this.mStartPoint = startPoint;
		this.mEndPoint = endPoint;
	}

	/**
	 * Performs the simulation (navigating the CFG forward).
	 * 
	 * @return The resulting values for the variable. Note that it can be a set
	 *         containing only the original value (i.e. the one provided to the
	 *         constructor) if no modification occurs or in case of error.
	 */
	public Set<Type> simulate() {
		Set<Type> result = new HashSet<>();
		/*
		 * We will perform a breadth-first visit with removal of repeated nodes
		 */
		Queue<Node> toVisit = new ArrayDeque<>();
		Set<Node> alreadyVisited = new HashSet<>();
		
		toVisit.add(new Node(this.mRaw, this.mStartPoint));
		
		while (!toVisit.isEmpty()) {
			Node currentNode = toVisit.remove();
			
			// Skip if already visited
			if (alreadyVisited.contains(currentNode)) {
				continue;
			}
			
			// Check if we reached the end
			if (currentNode.unit.equals(this.mEndPoint)) {
				return result;
			}
			
			// Add to visited nodes
			alreadyVisited.add(currentNode);
			
			/*
			 * Check if current statement performs a modification 
			 */
			
		}
		
		// We have an error or we didn't reach the end. Return the initial value
		result.clear();
		result.add(mRaw);
		return result;
	}

	protected Set<Node> getNextNode(Node current) {
		Set<Node> result = new HashSet<>(0);

		// Add successors
		for (Unit succ : mCfg.getSuccsOf(current.unit)) {
			result.add(new Node(current.value, succ));
		}

		// If this is a method call, inspect the callees
		if (mCfg.isCallStmt(current.unit)) {
			Collection<SootMethod> callees = mCfg.getCalleesOfCallAt(
					current.unit);
			for (SootMethod callee : callees) {
				for (Unit startPoint : mCfg.getStartPointsOf(callee)) {
					result.add(new Node(current.value, startPoint));
				}
			}
		}

		return result;
	}

}
