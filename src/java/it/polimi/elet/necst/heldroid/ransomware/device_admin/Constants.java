package it.polimi.elet.necst.heldroid.ransomware.device_admin;

public interface Constants {

	/* Files */
	static final String ANDROID_MANIFEST_FILE = "AndroidManifest.xml";

	/* Tags */
	static final String RECEIVER_TAG = "receiver";
	static final String META_DATA_TAG = "meta-data";
	static final String DEVICE_ADMIN_TAG = "device-admin";
	static final String USES_POLICIES_TAG = "uses-policies";
	static final String USES_PERMISSION_TAG = "uses-permission";
	static final String USES_PERMISSION_SDK_23_TAG = "uses-permission-sdk-23";
	static final String APPLICATION_TAG = "application";

	/* Attributes */
	static final String PERMISSION_ATTRIBUTE = "android:permission";
	static final String NAME_ATTRIBUTE = "android:name";
	static final String RESOURCE_ATTRIBUTE = "android:resource";

	/* Values */
	static final String BIND_DEVICE_ADMIN_VALUE = "android.permission.BIND_DEVICE_ADMIN";
	static final String DEVICE_ADMIN_VALUE = "android.app.device_admin";

	/* Regex */
	/**
	 * A regex for identifying Android xml file references, such as:
	 * {@code @[<package-name>:]<resource-type>/<resource-name>})
	 * This regex has 3 named groups:
	 * <ol>
	 * 	<li>{@code package}, that contains the optional package name</li>
	 * 	<li>{@code type}, that contains the resource type</li>
	 *  <li>{@code name}, that contains the resource name</li>
	 * </ol>
	 */
	static final String RESOURCE_REGEX = "^\\@(?:(?<package>\\w+(?:\\.\\w+)*)(?::))?(?<type>\\w+)\\/(?<name>\\w+)$";
}
