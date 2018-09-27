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
package eu.europa.esig.dss.tsl;

import java.io.Serializable;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Represents a condition defined in the trusted list on a certificate.
 *
 */
@SuppressWarnings("serial")
public abstract class Condition implements Serializable {

	/**
	 * Returns true if the condition is evaluated to true for the given certificate.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken} to be checked
	 * @return true if the condition is filled
	 */
	public abstract boolean check(final CertificateToken certificateToken);

	/**
	 * Returns a string representation of the condition
	 * 
	 * @param indent
	 *            the indentation to be used
	 * @return a human readable condition
	 */
	public abstract String toString(String indent);

}
