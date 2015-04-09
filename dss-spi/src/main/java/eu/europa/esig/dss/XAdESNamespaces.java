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
package eu.europa.esig.dss;

/**
 * This enum contains all known XAdES version with their namespace.
 *
 *
 *
 *
 *
 */
public final class XAdESNamespaces {

	public static final String XAdES141 = "http://uri.etsi.org/01903/v1.4.1#";
	public static final String XAdES132 = "http://uri.etsi.org/01903/v1.3.2#";
	public static final String XAdES122 = "http://uri.etsi.org/01903/v1.2.2#";
	public static final String XAdES111 = "http://uri.etsi.org/01903/v1.1.1#";

	public static String XAdES = XAdES132;

	protected static String XADES_SIGNING_CERTIFICATE = "xades:SigningCertificate";

	private XAdESNamespaces() {
	}

	/**
	 * This setter allows to change the default XAdES namespace. It can be useful when dealing with old applications.
	 * Note that there is no check on the value of the namespace. It's calling method responsibility.
	 *
	 * @param XAdES new default namespace
	 */
	public static void setXAdESDefaultNamespace(final String XAdES) {

		XAdESNamespaces.XAdES = XAdES;
		if (XAdES132.equals(XAdES)) {
			XADES_SIGNING_CERTIFICATE = "xades:SigningCertificate";
		} else if (XAdES111.equals(XAdES)) {
			XADES_SIGNING_CERTIFICATE = "xades111:SigningCertificate";
		}
	}

	/**
	 * Checks if the url is related to XAdES namespace. XAdES141 is excluded from this test as it concerns only the archive timestamp.
	 *
	 * @param url
	 * @return
	 */
	public static boolean exists(final String url) {

		return XAdES132.equals(url) || XAdES111.equals(url) || XAdES122.equals(url) || XAdES.equals(url);
	}

	public static String getXADES_SIGNING_CERTIFICATE() {
		return XADES_SIGNING_CERTIFICATE;
	}
}
