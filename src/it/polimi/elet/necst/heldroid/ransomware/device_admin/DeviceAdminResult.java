package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import soot.BooleanType;
import soot.DoubleType;
import soot.FloatType;
import soot.IntType;
import soot.LongType;
import soot.RefType;
import soot.ShortType;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;

/**
 * This class is a container for all the currently available Android Device
 * Administrator policies.
 * 
 * @author Nicola Dellarocca
 *
 */
public class DeviceAdminResult {

	/**
	 * All policies currently implemented in Android.
	 * 
	 * @author Nicola Dellarocca
	 *
	 */
	public enum Policy {
		USES_ENCRYPTED_STORAGE(null),
		USES_POLICY_DISABLE_CAMERA(null),
		USES_POLICY_DISABLE_KEYGUARD_FEATURES(null),
		USES_POLICY_EXPIRE_PASSWORD(null),
		USES_POLICY_FORCE_LOCK(null),
		USES_POLICY_LIMIT_PASSWORD(null),
		USES_POLICY_RESET_PASSWORD(new String[] {
				"android.app.admin.DevicePolicyManager->resetPassword" }),
		USES_POLICY_WATCH_LOGIN(null),
		USES_POLICY_WIPE_DATA(new String[] {
				"android.app.admin.DevicePolicyManager->wipeData" });

		/**
		 * The regex that related methods <b>must</b> satisfy.
		 */
		public static final String REGEX = "(.+?)->(.+?)";

		private String[] relatedMethods;

		private Policy(String[] relatedMethodNames) {
			this.relatedMethods = relatedMethodNames;
		}

		/**
		 * Whether the current policy is supported (i.e. if it has at least one
		 * related method).
		 * 
		 * @return <code>true</code> if it is supported, <code>false</code>
		 *         otherwise.
		 */
		public boolean isSupported() {
			return this.relatedMethods != null
					&& this.relatedMethods.length > 0;
		}

		/**
		 * Returns an array containing all the supported policies. If no policy
		 * is supported, the array will be empty. It is guaranteed that the
		 * result will never be <code>null</code>.
		 * 
		 * @return The supported policies, or an empty array if no policy is
		 *         supported.
		 */
		public static Policy[] getSupportedPolicies() {
			List<Policy> supportedPolicies = new ArrayList<>();

			for (Policy policy : Policy.values()) {
				if (policy.isSupported())
					supportedPolicies.add(policy);
			}

			return supportedPolicies.toArray(
					new Policy[supportedPolicies.size()]);
		}

		/**
		 * Checks whether the provided method is related to this policy. Please
		 * note that the method <b>must</b> respect the format:
		 * 
		 * <pre>
		 * {@code <declaring_class>-><method_name>}
		 * </pre>
		 * 
		 * for instance:
		 * 
		 * <pre>
		 * {@code java.lang.String->substring}
		 * </pre>
		 * 
		 * @param method
		 *            The method to check.
		 * @return <code>true</code> if the method is related to this policy,
		 *         <code>false</code> otherwise.
		 */
		public boolean isMethodRelated(SootMethod method) {
			if (method == null) {
				throw new IllegalArgumentException("Method must be non null");
			}
			
			if (this.relatedMethods == null)
				throw new IllegalStateException("Policy not supported yet");
			
			SootClass declClass = method.getDeclaringClass();
			
			StringBuilder builder = new StringBuilder(declClass.getName());
			
			builder.append("->");
			builder.append(method.getName());
//			builder.append('(');
//			
//			int nParams = method.getParameterCount();
//			
//			// Add params type
//			for (int i=0; i<nParams; i++) {
//				Type type = method.getParameterType(i);
//				
//				if (type instanceof RefType) {
//					builder.append(((RefType) type).getClassName());
//				} else if (type instanceof IntType) {
//					builder.append("int");
//				} else if (type instanceof LongType) {
//					builder.append("long");
//				} else if (type instanceof BooleanType) {
//					builder.append("boolean");
//				} else if (type instanceof FloatType) {
//					builder.append("float");
//				} else if (type instanceof DoubleType) {
//					builder.append("double");
//				} else if (type instanceof ShortType) {
//					builder.append("short");
//				} else {
//					throw new IllegalArgumentException("Cannot determine the type of params");
//				}
//				
//				builder.append(',');
//			}
//			
//			if (nParams > 0) {
//				// Remove trailing comma
//				builder.setLength(builder.length()-1);
//			}
//			
//			builder.append(')');
			
			String methodString = builder.toString();
			
			for (String relatedMethod : relatedMethods) {
				if (relatedMethod.equals(methodString)) {
					return true;
				}
			}
			
			return false;
		}

		/**
		 * Returns the methods related to this policy. Please note that it could
		 * be <code>null</code> if the policy is not supported.
		 * 
		 * @see Policy#isSupported();
		 * 
		 * @return The array of related methods (with length &ge; 1) or
		 *         <code>null</code> if the policy is not supported.
		 */
		public ArrayList<String> getRelatedMethods() {
			return new ArrayList<String>(Arrays.asList(relatedMethods));
		}

		/**
		 * Returns the AndroidManifest entry equivalent to this policy.
		 * 
		 * @return The Android Manifest entry equivalent to this policy (e.g.
		 *         {@link #USES_ENCRYPTED_STORAGE} inside the manifest is
		 *         represented by the string "encrypted-storage").
		 */
		public String getManifestEntry() {
			String result = this.name()
								.toLowerCase();
			result = result	.replace("USES_", "")
							.replace("POLICY_", "")
							.replaceAll("_", "-");

			return result;
		}

		/**
		 * Tries to parse a string and convert it to one of the possible values
		 * of {@link Policy}.
		 * 
		 * @param policy
		 *            The string to parse.
		 * @return The corresponding {@link Policy}.
		 * @throws IllegalStateException
		 *             if the specified enum type has no constant with the
		 *             specified name.
		 * @throws NullPointerException
		 *             if {@code policy} is {@code null}.
		 */
		public static Policy parseString(String policy)
				throws IllegalStateException, NullPointerException {
			policy = policy	.toUpperCase()
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
	private boolean deviceAdminUsed;
	private boolean isFromReflection;

	/**
	 * Creates an empty instance.
	 */
	public DeviceAdminResult() {
		this.policies = new LinkedList<>();
	}

	/**
	 * Creates an instance containing the provided policies.
	 * 
	 * @param policies
	 *            The policies to include.
	 */
	public DeviceAdminResult(List<Policy> policies, boolean isFromReflection) {
		this();
		policies.addAll(policies);
	}

	public void addAll(Collection<Policy> policies) {
		policies.addAll(policies);
	}
	
	/**
	 * @param isFromReflection the isFromReflection to set
	 */
	public void setFromReflection(boolean isFromReflection) {
		this.isFromReflection = isFromReflection;
	}
	
	/**
	 * @return the isFromReflection
	 */
	public boolean isFromReflection() {
		return isFromReflection;
	}

	public List<Policy> getPolicies() {
		return policies;
	}

	/**
	 * Replaces all the previously inserted policies with the ones provided.
	 * 
	 * @param policies
	 *            The new policies to be included.
	 */
	public void setPolicies(List<Policy> policies) {
		this.policies = policies;
	}

	public void addPolicy(Policy policy) {
		if (policies == null) {
			policies = new LinkedList<Policy>();
		}

		policies.add(policy);
	}

	/**
	 * Removes all previously included policies.
	 */
	public void clearPolicies() {
		if (policies != null) {
			policies.clear();
		}
	}

	public boolean isDeviceAdminUsed() {
		return deviceAdminUsed;
	}

	public void setDeviceAdminUsed(boolean deviceAdminUsed) {
		this.deviceAdminUsed = deviceAdminUsed;
	}

}
