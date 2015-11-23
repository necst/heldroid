package it.polimi.elet.necst.heldroid.ransomware.device_admin;

public interface Constants {

	/* Files */
	static final String ANDROID_MANIFEST_FILE = "AndroidManifest.xml";

	/* Tags */
	static final String RECEIVER_TAG = "receiver";
	static final String META_DATA_TAG = "meta-data";
	static final String DEVICE_ADMIN_TAG = "device-admin";
	static final String USES_POLICIES = "uses-policies";

	/* Attributes */
	static final String PERMISSION_ATTRIBUTE = "android:permission";
	static final String NAME_ATTRIBUTE = "android:name";
	static final String RESOURCE_ATTRIBUTE = "android:resource";

	/* Values */
	static final String BIND_DEVICE_ADMIN_VALUE = "android.permission.BIND_DEVICE_ADMIN";
	static final String DEVICE_ADMIN_VALUE = "android.app.device_admin";

	/* Regex */
	static final String RESOURCE_REGEX = "\\@(\\w+)\\/([\\w_]+)";
}
