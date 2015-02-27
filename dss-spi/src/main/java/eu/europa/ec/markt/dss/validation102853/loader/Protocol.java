/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.loader;

/**
 * This enum lists all network protocols that can be used during the signature creation or validation: OCSP, CRL, AIA, TSL...
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public enum Protocol {

	FILE("file"), HTTP("http"), HTTPS("https"), LDAP("ldap"), FTP("ftp");

	private String name;

	private Protocol(final String name) {

		this.name = name;
	}

	/**
	 * @return the name of the protocol
	 */
	public String getName() {
		return name;
	}

	/**
	 * Indicates if the given string represents HTTPS protocol.
	 *
	 * @param name {@code String} to be checked
	 * @return true or false
	 */
	public static boolean isHttps(final String name) {
		return HTTPS.name.equalsIgnoreCase(name);
	}

	/**
	 * Indicates if the given string represents HTTP protocol.
	 *
	 * @param name {@code String} to be checked
	 * @return true or false
	 */
	public static boolean isHttp(final String name) {
		return HTTP.name.equalsIgnoreCase(name);
	}

	/**
	 * Indicates if the given URL uses FILE protocol
	 *
	 * @param urlString to be checked
	 * @return true or false
	 */
	public static boolean isFileUrl(final String urlString) {
		return urlString !=null && urlString.startsWith(FILE.name);
	}

	/**
	 * Indicates if the given URL uses HTTP protocol
	 *
	 * @param urlString to be checked
	 * @return true or false
	 */
	public static boolean isHttpUrl(final String urlString) {
		return urlString !=null && urlString.startsWith(HTTP.name);
	}

	/**
	 * Indicates if the given URL uses FTP protocol
	 *
	 * @param urlString to be checked
	 * @return true or false
	 */
	public static boolean isFtpUrl(final String urlString) {
		return urlString !=null && urlString.startsWith(FTP.name);
	}

	/**
	 * Indicates if the given URL uses LDAP protocol
	 *
	 * @param urlString to be checked
	 * @return true or false
	 */
	public static boolean isLdapUrl(final String urlString) {
		return urlString !=null && urlString.startsWith(LDAP.name);
	}

	/**
	 * Indicates if the given URL uses the current protocol
	 *
	 * @param urlString to be checked
	 * @return true or false
	 */
	public boolean isTheSame(final String urlString) {

		return urlString != null && urlString.startsWith(name);
	}

	/**
	 * This method try to retrieve the protocol indicated by the given URL string.
	 *
	 * @param urlString to be analysed
	 * @return found {@code Protocol} or {@code null}
	 */
	public static Protocol getFrom(final String urlString) {

		if (HTTP.isTheSame(urlString)) {
			return HTTP;
		} else if (HTTPS.isTheSame(urlString)) {
			return HTTPS;
		} else if (LDAP.isTheSame(urlString)) {
			return LDAP;
		} else if (FTP.isTheSame(urlString)) {
			return FTP;
		} else if (FILE.isTheSame(urlString)) {
			return FILE;
		}
		return null;
	}
}
