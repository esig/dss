/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.applet.util;

import java.io.IOException;
import java.net.URI;
import java.util.ResourceBundle;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 */
public final class ResourceUtils {

	private static final ResourceBundle BUNDLE_I18N;

	static {
		BUNDLE_I18N = ResourceBundle.getBundle("eu/europa/esig/dss/applet/i18n");
	}

	/**
	 *
	 * @param key
	 * @return
	 */
	public static String getI18n(final String key) {
		return BUNDLE_I18N.getString(key);
	}

	/**
	 *
	 * @param uri
	 * @throws IOException
	 */
	public static void openFile(final URI uri) throws IOException {
		Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + uri.toString());
	}

	private ResourceUtils() {
	}

}
