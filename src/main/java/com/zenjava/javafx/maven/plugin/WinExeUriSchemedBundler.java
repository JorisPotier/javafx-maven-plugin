package com.zenjava.javafx.maven.plugin;

import com.oracle.tools.packager.ConfigException;
import com.oracle.tools.packager.StandardBundlerParam;
import com.oracle.tools.packager.UnsupportedPlatformException;
import com.oracle.tools.packager.windows.WinExeBundler;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WinExeUriSchemedBundler extends WinExeBundler {

	public static final String REGISTRY_HEADER = "[Registry]";

	private static final StandardBundlerParam<String> PROTOCOL_URI_SCHEME;
	private static final StandardBundlerParam<String> PROTOCOL_URI_NAME;

	static {
		PROTOCOL_URI_SCHEME = new StandardBundlerParam<>(
				"uriSchemeProtocol",
				"URI Scheme Protocol",
				"uriSchemeProtocol",
				String.class,
				params -> {
					String nm = StandardBundlerParam.APP_NAME.fetchFrom(params);
					if (nm == null) return null;
					return nm.replaceAll("[^-a-zA-Z\\.0-9]", "");
				},
				(s, p) -> s);
		PROTOCOL_URI_NAME = new StandardBundlerParam<>(
				"uriSchemeName",
				"URI Scheme Name",
				"uriSchemeName",
				String.class,
				StandardBundlerParam.APP_NAME::fetchFrom,
				(s, p) -> s);
	}

	private String protocolUriScheme;
	private String protocolUriName;

	@Override
	public String getBundleType() {
		return "INSTALLER_URI_SCHEMED";
	}


	@Override
	public boolean validate(Map<String, ? super Object> map) throws UnsupportedPlatformException, ConfigException {
		final boolean validate = super.validate(map);
		if (!validate) {
			return false;
		}

		protocolUriScheme = PROTOCOL_URI_SCHEME.fetchFrom(map);
		protocolUriName = PROTOCOL_URI_NAME.fetchFrom(map);

		return true;
	}

	@Override
	protected String preprocessTextResource(String publicName, String category,
	                                        String defaultName, Map<String, String> pairs,
	                                        boolean verbose, File publicRoot) throws IOException {
		String textResource = super.preprocessTextResource(publicName, category, defaultName, pairs, verbose, publicRoot);
		return preprocessUriProtocolRegistryEntries(pairs, textResource);
	}

	String preprocessUriProtocolRegistryEntries(Map<String, String> pairs, String textResource) {

		final String runFilename = pairs.get("RUN_FILENAME");

		if (!empty(textResource) && !empty(runFilename)) {
			if (!textResource.contains(REGISTRY_HEADER)) {
				while (!textResource.endsWith("\r\n\r\n")) {
					textResource += "\r\n";
				}
				textResource = textResource + REGISTRY_HEADER + "\r\n" + getProtocolUriRegistryEntries(runFilename);
			} else {
				Pattern p = Pattern.compile("(.*\\r\\n)*" + Pattern.quote(REGISTRY_HEADER) + "\\r\\n(.+\\r\\n)+");
				Matcher m = p.matcher(textResource);
				StringBuffer bufStr = new StringBuffer();

				while (m.find()) {
					String rep = m.group();
					m.appendReplacement(bufStr, rep + getProtocolUriRegistryEntries(runFilename).toString().replace("\\", "\\\\"));
				}
				m.appendTail(bufStr);

				textResource = bufStr.toString();
			}
		}
		return textResource;
	}

	private StringBuilder getProtocolUriRegistryEntries(String runFilename) {
		return new StringBuilder()
				.append("Root: HKCR; Subkey: \"")
				.append(protocolUriScheme)
				.append("\"; ValueType: \"string\"; ValueData: \"URL:")
				.append(protocolUriName).append(" Protocol\"; Flags: uninsdeletekey\r\n")
				.append("Root: HKCR; Subkey: \"")
				.append(protocolUriScheme).append("\"; ValueType: \"string\"; ValueName: \"URL Protocol\"; ValueData: \"\"\r\n")
				.append("Root: HKCR; Subkey: \"")
				.append(protocolUriScheme)
				.append("\\DefaultIcon\"; ValueType: \"string\"; ValueData: \"{app}\\")
				.append(runFilename)
				.append(".exe,0\"\r\n")
				.append("Root: HKCR; Subkey: \"")
				.append(protocolUriScheme)
				.append("\\shell\\open\\command\"; ValueType: \"string\"; ValueData: \"\"\"{app}\\")
				.append(runFilename)
				.append(".exe\"\"\"\r\n");
	}

	private boolean empty(String s) {
		return s == null || s.length() == 0;
	}
}
