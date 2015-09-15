/*
 * Copyright 2012 Daniel Zwolenski.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

/**
 * Warning, SystemWide property must be set to true in order to have admin rights which are required to write in the Windows registry.
 */
public class WinExeUriSchemedBundler extends WinExeBundler {

	public static final String REGISTRY_HEADER = "[Registry]";

	private static final StandardBundlerParam<String> PROTOCOL_URI_SCHEME;
	private static final StandardBundlerParam<String> PROTOCOL_URI_NAME;
	private static final StandardBundlerParam<Boolean> STARTUP_LAUNCH;

	static {
		PROTOCOL_URI_SCHEME = new StandardBundlerParam<>(
				"uriSchemeProtocol",
				"URI Scheme Protocol",
				"uriSchemeProtocol",
				String.class,
				params -> {
					String nm = StandardBundlerParam.APP_NAME.fetchFrom(params);
					if (nm == null) {
						return null;
					}
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

		STARTUP_LAUNCH = new StandardBundlerParam<>(
				"startupLaunch",
				"Launch at OS startup",
				"startupLaunch",
				Boolean.class,
				params -> false,
				(s, p) -> Boolean.valueOf(s));
	}

	private String protocolUriScheme;
	private String protocolUriName;
	private Boolean startupLaunch;

	@Override
	public String getBundleType() {
		return "INSTALLER_URI_SCHEMED";
	}


	@Override
	public boolean validate(Map<String, ? super Object> params) throws UnsupportedPlatformException, ConfigException {
		final boolean validate = super.validate(params);
		if (!validate) {
			return false;
		}

		protocolUriScheme = PROTOCOL_URI_SCHEME.fetchFrom(params);
		protocolUriName = PROTOCOL_URI_NAME.fetchFrom(params);
		startupLaunch = STARTUP_LAUNCH.fetchFrom(params);

		return true;
	}

	@Override
	protected String preprocessTextResource(String publicName, String category,
	                                        String defaultName, Map<String, String> pairs,
	                                        boolean verbose, File publicRoot) throws IOException {
		String textResource = super.preprocessTextResource(publicName, category, defaultName, pairs, verbose, publicRoot);
		return preprocessUriProtocolRegistryEntries(pairs, textResource);
	}

	String preprocessUriProtocolRegistryEntries(final Map<String, String> pairs, final String textResource) {
		final String runFilename = pairs.get("RUN_FILENAME");
		String out = textResource;

		if (!empty(out) && !empty(runFilename)) {
			if (!out.contains(REGISTRY_HEADER)) {
				while (!out.endsWith("\r\n\r\n")) {
					out += "\r\n";
				}
				out += REGISTRY_HEADER + "\r\n" + getProtocolUriRegistryEntries(runFilename);
			} else {
				Pattern p = Pattern.compile("(.*\\r\\n)*" + Pattern.quote(REGISTRY_HEADER) + "\\r\\n(.+\\r\\n)+");
				Matcher m = p.matcher(out);
				StringBuffer bufStr = new StringBuffer();

				while (m.find()) {
					String rep = m.group();
					m.appendReplacement(bufStr, rep + getProtocolUriRegistryEntries(runFilename).toString().replace("\\", "\\\\"));
				}
				m.appendTail(bufStr);

				out = bufStr.toString();
			}
		}
		return out;
	}

	private StringBuilder getProtocolUriRegistryEntries(String runFilename) {
		final StringBuilder regEntries = new StringBuilder()
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
		if (startupLaunch) {
			regEntries
					.append("Root: HKLM; Subkey: \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"; ValueType: string; ValueName: \"")
					.append(runFilename)
					.append("\"; ValueData: \"\"\"{app}\\")
					.append(runFilename)
					.append(".exe\"\"\"; Flags: uninsdeletevalue\r\n");
		}
		return regEntries;
	}

	private boolean empty(String s) {
		return s == null || s.length() == 0;
	}
}
