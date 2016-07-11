/**
 * 
 */
package it.polimi.elet.necst.heldroid.ransomware.photo;

/**
 * 14 giu 2016
 * @author Nicola Dellarocca
 *
 */
public class PhotoAdminResult {
	
	private boolean fromReflection;
	private boolean photoDetected;
	
	/**
	 * @return the fromReflection
	 */
	public boolean isFromReflection() {
		return fromReflection;
	}
	
	/**
	 * @return the photoDetected
	 */
	public boolean isPhotoDetected() {
		return photoDetected;
	}
	
	/**
	 * @param fromReflection the fromReflection to set
	 */
	public void setFromReflection(boolean fromReflection) {
		this.fromReflection = fromReflection;
	}
	
	/**
	 * @param photoDetected the photoDetected to set
	 */
	public void setPhotoDetected(boolean photoDetected) {
		this.photoDetected = photoDetected;
	}

}
