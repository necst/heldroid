package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * This class acts like a container for all the currently available
 * Andriod Device Administrator policies.
 * 
 * @author Nicola
 *
 */
public class DeviceAdminResult {
	
	/**
	 * All currently available policies
	 * @author Nicola
	 *
	 */
	public enum Policy {
		USES_ENCRYPTED_STORAGE,
		USES_POLICY_DISABLE_CAMERA,
		USES_POLICY_DISABLE_KEYGUARD_FEATURES,
		USES_POLICY_EXPIRE_PASSWORD,
		USES_POLICY_FORCE_LOCK,
		USES_POLICY_LIMIT_PASSWORD,
		USES_POLICY_RESET_PASSWORD,
		USES_POLICY_WATCH_LOGIN,
		USES_POLICY_WIPE_DATA;
		
		/**
		 * @return The Android Manifest entry equivalent to this policy (e.g. {@link #USES_ENCRYPTED_STORAGE}
		 * inside the manifest is represented by the string "encrypted-storage").
		 */
		public String getManifestEntry() {
			String result = this.name().toLowerCase();
			result = result.replace("USES_", "")
					.replace("POLICY_", "")
					.replaceAll("_", "-");
			
			return result;
		}
		
		/**
		 * Tries to parse a string and convert it to one of the possible values of {@link Policy}.
		 * @param policy The string to parse.
		 * @return The corresponding {@link Policy}.
		 * @throws IllegalStateException if the specified enum type has no constant with the specified name.
		 * @throws NullPointerException if {@code policy} is {@code null}.
		 */
		public static Policy parseString(String policy) throws IllegalStateException, NullPointerException {
			policy = policy.toUpperCase()
					.replaceAll("-", "_");
			
			if (policy.equals("ENCRYPTED_STORAGE")) {
				policy = "USES_" + policy;
			} else {
				policy = "USES_POLICY_" + policy;
			}
			
			return Policy.valueOf(policy);
		}
	}
	
	private List<Policy> policies;
	
	public DeviceAdminResult() {
		this.policies = new LinkedList<>();
	}
	
	public DeviceAdminResult(List<Policy> policies) {
		this();
		policies.addAll(policies);
	}
	
	public void addAll(Collection<Policy> policies) {
		policies.addAll(policies);
	}
	
	public List<Policy> getPolicies() {
		return policies;
	}
	
	public void setPolicies(List<Policy> policies) {
		this.policies = policies;
	}
	
	public void addPolicy(Policy policy) {
		if (policies == null) {
			policies = new LinkedList<Policy>();
		}
		
		policies.add(policy);
	}
	
	public void clearPolicies() {
		if (policies != null) {
			policies.clear();
		}
	}

}
