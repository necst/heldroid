package it.polimi.elet.necst.heldroid.ransomware.device_admin;

import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.APPLICATION_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.BIND_DEVICE_ADMIN_VALUE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.DEVICE_ADMIN_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.DEVICE_ADMIN_VALUE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.META_DATA_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.NAME_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.PERMISSION_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RECEIVER_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RESOURCE_ATTRIBUTE;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.RESOURCE_REGEX;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_PERMISSION_SDK_23_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_PERMISSION_TAG;
import static it.polimi.elet.necst.heldroid.ransomware.device_admin.Constants.USES_POLICIES_TAG;

import java.io.File;
import java.io.FilenameFilter;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import it.polimi.elet.necst.heldroid.apk.DecodedPackage;
import it.polimi.elet.necst.heldroid.ransomware.device_admin.DeviceAdminResult.Policy;
import it.polimi.elet.necst.heldroid.utils.Wrapper;
import it.polimi.elet.necst.heldroid.utils.Xml;

/**
 * This class analyzes an APK file in order to discover if the app uses Android
 * Device Administrator API.
 * 
 * @author Nicola
 *
 */
public class DeviceAdminDetector {
	/*
	 ***********************************************
	 * Please note the static import for constants *
	 ***********************************************
	 */

	// Resource files are like: @type/file_name
	private static final Pattern POLICIES_FILE_REGEX = Pattern.compile(
			RESOURCE_REGEX);

	private DecodedPackage target;
	private DocumentBuilderFactory dbFactory;
	private DocumentBuilder db;

	/**
	 * Creates a {@code DeviceAdminDetector} instance
	 * @throws ParserConfigurationException if it is not possible to
	 * create an XML parser for the AndroidManifest.xml file.
	 */
	public DeviceAdminDetector() throws ParserConfigurationException {
		this.dbFactory = DocumentBuilderFactory.newInstance();
		this.db = dbFactory.newDocumentBuilder();
	}

	/**
	 * Scans the {@code manifest} to discover if the app uses the
	 * {@link Constants#BIND_DEVICE_ADMIN_VALUE} permission.
	 * 
	 * @param manifest
	 *            The manifest in which the permission will be searched.
	 * @return {@code true} if the manifest contains such permission,
	 *         {@code false} otherwise.
	 */
	private boolean findDeviceAdminPermission(Document manifest) {
		Element root = manifest.getDocumentElement();

		// First search inside <uses-permission> tags
		Collection<Element> usesPermissionTags = Xml.getElementsByTagName(root,
				USES_PERMISSION_TAG);
		for (Element usesPermissionTag : usesPermissionTags) {
			if (usesPermissionTag.hasAttribute(NAME_ATTRIBUTE)
					&& usesPermissionTag.getAttribute(NAME_ATTRIBUTE)
										.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}
		}
		// Allow garbage collection
		usesPermissionTags = null;

		// Now look inside <uses-permission-sdk-23> tags
		Collection<Element> usesPermission23Tags = Xml.getElementsByTagName(
				root, USES_PERMISSION_SDK_23_TAG);
		for (Element usesPermission23Tag : usesPermission23Tags) {
			if (usesPermission23Tag.hasAttribute(NAME_ATTRIBUTE)
					&& usesPermission23Tag	.getAttribute(NAME_ATTRIBUTE)
											.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}
		}
		usesPermission23Tags = null;

		// Now look inside the <application> tag
		Element application = Xml.getChildElement(root, APPLICATION_TAG);
		if (application.hasAttribute(PERMISSION_ATTRIBUTE)
				&& application	.getAttribute(PERMISSION_ATTRIBUTE)
								.equals(BIND_DEVICE_ADMIN_VALUE)) {
			return true;
		}
		application = null;

		// Then look inside <receiver> tag
		Collection<Element> receivers = Xml.getElementsByTagName(root,
				RECEIVER_TAG);
		for (Element receiver : receivers) {
			if (receiver.hasAttribute(PERMISSION_ATTRIBUTE)
					&& receiver	.getAttribute(PERMISSION_ATTRIBUTE)
								.equals(BIND_DEVICE_ADMIN_VALUE)) {
				return true;
			}

			// Look also inside <meta-data> for such permission
			Element metadata = Xml.getChildElement(receiver, META_DATA_TAG);
			if (metadata != null) {
				if (metadata.hasAttribute(PERMISSION_ATTRIBUTE)
						&& metadata	.getAttribute(PERMISSION_ATTRIBUTE)
									.equals(BIND_DEVICE_ADMIN_VALUE)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Scans the Android Manifest to (possibly) find the resource containing
	 * Device Administrator policies.
	 * 
	 * @return The string identifying an Android resource (in the form
	 *         {@code @<type>/<file_name>} or {@code null}, if the Manifest does
	 *         not contain such reference.
	 */
	private String findDeviceAdminPoliciesFile() {
		try {
			Document document = db.parse(target.getAndroidManifest());
			Element root = document.getDocumentElement();

			Collection<Element> receivers = Xml.getElementsByTagName(root,
					RECEIVER_TAG);

			boolean hasDeviceAdminPermission = findDeviceAdminPermission(
					document);
			if (!hasDeviceAdminPermission) {
				return null;
			}

			/*
			 * At this point the manifest contains such permission. We need to
			 * find the receiver that contains the appropriate <meta-data> child
			 * (i.e. that contains the device admin policies file reference)
			 */
			for (Element receiver : receivers) {
				// Get <meta-data> child
				Element metadata = Xml.getChildElement(receiver, META_DATA_TAG);
				if (metadata != null) {
					if (metadata.hasAttribute(NAME_ATTRIBUTE)
							&& metadata	.getAttribute(NAME_ATTRIBUTE)
										.equals(DEVICE_ADMIN_VALUE)) {

						if (metadata.hasAttribute(RESOURCE_ATTRIBUTE)) {
							return metadata.getAttribute(RESOURCE_ATTRIBUTE);
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Exception: " + e);
		}
		return null;
	}

	/**
	 * Parses {@code policiesFile} trying to extract all (known) policies.
	 * 
	 * See {@link DeviceAdminResult.Policy} for the list of currently supported
	 * policies.
	 * 
	 * @param policiesFile
	 * @return A wrapper for {@link DeviceAdminResult} object. The wrapper will
	 *         never be {@code null}.
	 */
	private Wrapper<DeviceAdminResult> parseDeviceAdminPoliciesFile(
			File policiesFile) {

		// Holds the result
		DeviceAdminResult result = null;

		if (policiesFile.exists()) {
			try {
				Document document = db.parse(policiesFile);
				Element root = document.getDocumentElement();

				if (root.getTagName().equals(DEVICE_ADMIN_TAG)) {
					// This app makes use of <device-admin>
					result = new DeviceAdminResult();
					result.setDeviceAdminUsed(true);

					// This tag's child are the policies
					Element usesPolicies = Xml.getChildElement(root,
							USES_POLICIES_TAG);
					if (usesPolicies != null) {

						// Will contain a list of policies
						List<Element> policies = Xml.getChildElements(
								usesPolicies);
						if (policies.size() > 0) {
							// Add all policies to result
							for (Element policy : policies) {
								// Try to parse policies, otherwise skip them
								try {
									Policy p = Policy.parseString(
											policy.getTagName());
									result.addPolicy(p);
								} catch (Exception e) {
									System.err.println(
											"Skipping unknown policy: "
													+ policy);
								}
							}
						}

					}
				}

			} catch (Exception e) {
				System.err.println("Exception: " + e);
			}
		}

		return new Wrapper<DeviceAdminResult>(result);
	}

	/**
	 * Scans the APK trying to discover if the app makes use of Android Device
	 * Administrator API.
	 * 
	 * @return a wrapper containing a {@link DeviceAdminResult} object. The
	 *         wrapper will never be {@code null}. If the app does not use the
	 *         Device Administrator API, the result will be a wrapper for a
	 *         {@code null} object (i.e. {@code wrapper.value} will be
	 *         {@code null}.
	 * @throws IllegalStateException
	 *             if a {@link #setTarget(DecodedPackage) target} is not set
	 */
	public Wrapper<DeviceAdminResult> detect() throws IllegalStateException {
		if (target == null) {
			throw new IllegalStateException("Target is not set");
		}

		String deviceAdminPoliciesFile = findDeviceAdminPoliciesFile();

		if (deviceAdminPoliciesFile != null) {
			Matcher matcher = POLICIES_FILE_REGEX.matcher(
					deviceAdminPoliciesFile);
			if (matcher.matches()) {

				// This file should always be in XML folder
				File xmlDirectory = new File(target.getResourcesDirectory(),
						"xml");
				if (xmlDirectory.exists() && xmlDirectory.isDirectory()) {

					final String fileName = matcher.group(2);

					/*
					 * Some files have no extension, so let's check both with
					 * and without .xml extension
					 */
					File[] matchingFiles = xmlDirectory.listFiles(
							new FilenameFilter() {

								@Override
								public boolean accept(File dir, String name) {
									String regex = "^" + fileName
											+ "(\\.\\w+)?$";
									return name.matches(regex);
								}

							});

					// Should never happen
					if (matchingFiles.length == 0) {
						System.err.println(
								"Error: policies file not found in res/xml/ folder");
						return new Wrapper<DeviceAdminResult>(null);
					}

					// File policiesFile = new File(xmlDirectory, fileName);
					File policiesFile = matchingFiles[0];

					return parseDeviceAdminPoliciesFile(policiesFile);
				}
			}
		}

		return new Wrapper<DeviceAdminResult>(null);
	}

	/**
	 * 
	 * @param target
	 *            The target for the APK to scan.
	 */
	public void setTarget(DecodedPackage target) {
		this.target = target;
	}
}
