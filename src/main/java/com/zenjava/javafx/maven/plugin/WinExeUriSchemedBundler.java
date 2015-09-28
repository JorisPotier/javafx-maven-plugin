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

import com.oracle.tools.packager.BundlerParamInfo;
import com.oracle.tools.packager.ConfigException;
import com.oracle.tools.packager.StandardBundlerParam;
import com.oracle.tools.packager.UnsupportedPlatformException;
import com.oracle.tools.packager.windows.WinExeBundler;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Warning, SystemWide property must be set to true in order to have admin rights which are required to write in the Windows registry.
 */
class WinExeUriSchemedBundler extends WinExeBundler {

	private static final String RUN_FILENAME_KEY = "RUN_FILENAME";
	private static final String HEADER_REGISTRY = "[Registry]";
	private static final String HEADER_TASKS = "[Tasks]";

	private static final StandardBundlerParam<String> PROTOCOL_URI_SCHEME;
	private static final StandardBundlerParam<String> PROTOCOL_URI_NAME;
	private static final StandardBundlerParam<Boolean> STARTUP_LAUNCH;
	private static final StandardBundlerParam<Boolean> STARTUP_LAUNCH_USER_LEVEL;

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

		STARTUP_LAUNCH_USER_LEVEL = new StandardBundlerParam<>(
				"startupLaunchUserLevel",
				"Launch only for this user",
				"startupLaunchUserLevel",
				Boolean.class,
				params -> false,
				(s, p) -> Boolean.valueOf(s));
	}

	private String protocolUriScheme;
	private String protocolUriName;
	private boolean startupLaunch;
	private boolean startupLaunchUserLevel;

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
		startupLaunch = toBoolean(STARTUP_LAUNCH.fetchFrom(params));
		startupLaunchUserLevel = toBoolean(STARTUP_LAUNCH_USER_LEVEL.fetchFrom(params));
		if (startupLaunchUserLevel && !startupLaunch) {
			throw new ConfigException(
					String.format("Parameter '%s' needs the parameter '%s' to be set", STARTUP_LAUNCH_USER_LEVEL.getID(), STARTUP_LAUNCH.getID()),
					String.format("Remove '%s' or change the value of '%s'", STARTUP_LAUNCH_USER_LEVEL.getID(), STARTUP_LAUNCH.getID()));
		}

		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Collection<BundlerParamInfo<?>> getBundleParameters() {
		LinkedHashSet results = new LinkedHashSet();
		results.addAll(super.getBundleParameters());
		results.addAll(getUriSchemedBundleParameters());
		return results;
	}

	private static Collection<BundlerParamInfo<?>> getUriSchemedBundleParameters() {
		return Arrays.asList(new BundlerParamInfo[]{PROTOCOL_URI_SCHEME, PROTOCOL_URI_NAME, STARTUP_LAUNCH, STARTUP_LAUNCH_USER_LEVEL});
	}

	@Override
	protected String preprocessTextResource(String publicName, String category,
	                                        String defaultName, Map<String, String> pairs,
	                                        boolean verbose, File publicRoot) throws IOException {
		String textResource = super.preprocessTextResource(publicName, category, defaultName, pairs, verbose, publicRoot);
		return preprocessUriProtocolRegistryEntries(pairs, textResource);
	}

	private String preprocessUriProtocolRegistryEntries(Map<String, String> pairs, final String textResource) {

		final String runFilename = pairs.get(RUN_FILENAME_KEY);
		String out = textResource;

		if (notEmpty(out) && notEmpty(runFilename)) {
			out = addValuesUnderHeader(out, HEADER_REGISTRY, getProtocolUriRegistryEntries(runFilename));
			if (startupLaunch) {
				out = addValuesUnderHeader(out, HEADER_REGISTRY, getRunAtStartupRegistryEntries(runFilename, startupLaunchUserLevel));
				out = addValuesUnderHeader(out, HEADER_TASKS, getRunAtStartupTask());
			}
		}
		return out;
	}

	private String addValuesUnderHeader(final String input, final String header, final String values) {
		String out = input;
		final String eol = "\r\n";
		if (!out.contains(header)) {
			while (!out.endsWith(eol + eol)) {
				out += eol;
			}
			out += header + eol + values;
		} else {
			Pattern p = Pattern.compile("(.*\\r\\n)*" + Pattern.quote(header) + "\\r\\n((.+\\r\\n)*.+(\\r\\n)*?)");
			Matcher m = p.matcher(out);
			StringBuffer bufStr = new StringBuffer();

			while (m.find()) {
				String group = m.group();
				if (!group.endsWith(eol)) {
					group += eol;
				}
				m.appendReplacement(bufStr, (group + values).replace("\\", "\\\\"));
			}
			m.appendTail(bufStr);

			out = bufStr.toString();
		}
		return out;
	}

	private boolean notEmpty(final String s) {
		return s != null && s.length() != 0;
	}

	private String getProtocolUriRegistryEntries(final String runFilename) {
		return String.format(
				"Root: HKCR; Subkey: \"%s\"; ValueType: \"string\"; ValueData: \"URL:%s Protocol\"; Flags: uninsdeletekey\r\n" +
						"Root: HKCR; Subkey: \"%s\"; ValueType: \"string\"; ValueName: \"URL Protocol\"; ValueData: \"\"\r\n" +
						"Root: HKCR; Subkey: \"%s\\DefaultIcon\"; ValueType: \"string\"; ValueData: \"{app}\\%s.exe,0\"\r\n" +
						"Root: HKCR; Subkey: \"%s\\shell\\open\\command\"; ValueType: \"string\"; ValueData: \"\"\"{app}\\%s.exe\"\"\"\r\n",
				protocolUriScheme, protocolUriName, protocolUriScheme, protocolUriScheme, runFilename, protocolUriScheme, runFilename);
	}

	private String getRunAtStartupRegistryEntries(final String runFilename, final boolean startupLaunchUserLevel) {
		final String entry = startupLaunchUserLevel ?
				"Root: HKCU; Subkey: \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"; ValueType: string; ValueName: \"%s\"; ValueData: \"\"\"{app}\\%s.exe\"\"\"; Flags: uninsdeletevalue; Tasks:StartupLaunchTask;\r\n" :
				"Root: HKLM; Subkey: \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"; ValueType: string; ValueName: \"%s\"; ValueData: \"\"\"{app}\\%s.exe\"\"\"; Flags: uninsdeletevalue; Tasks:StartupLaunchTask;\r\n";
		return String.format(entry, runFilename, runFilename);
	}

	private String getRunAtStartupTask() {
		return "Name: \"StartupLaunchTask\"; Description: \"Automatically start on login\";";
	}

	public static boolean toBoolean(Boolean bool) {
		return bool != null && bool;
	}
}
