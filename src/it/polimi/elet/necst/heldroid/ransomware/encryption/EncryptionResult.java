package it.polimi.elet.necst.heldroid.ransomware.encryption;

import soot.jimple.infoflow.results.InfoflowResults;

public class EncryptionResult {
	
	private InfoflowResults infoFlowResults;
	private boolean writable;
	
	public InfoflowResults getInfoFlowResults() {
		return infoFlowResults;
	}
	
	public boolean isWritable() {
		return writable;
	}
	
	public void setWritable(boolean writable) {
		this.writable = writable;
	}
	
	public void setInfoFlowResults(InfoflowResults infoFlowResults) {
		this.infoFlowResults = infoFlowResults;
	}	

}
