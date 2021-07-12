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
package eu.europa.esig.dss.enumerations;

/**
 * Defines the qualification status of a certificate
 *
 */
public enum CertificateQualifiedStatus {

	/** Qualified */
	QC("Qualified"),

	/** Not qualified */
	NOT_QC("Not qualified");

	/** User-friendly definition of a qualification status */
	private final String label;

	/**
	 * Default constructor
	 *
	 * @param label {@link String}
	 */
	CertificateQualifiedStatus(String label) {
		this.label = label;
	}

	/**
	 * Returns a user-friendly certificate qualification label
	 *
	 * @return {@link String}
	 */
	public String getLabel() {
		return label;
	}

	/**
	 * This method verifies if the given {@code CertificateQualifiedStatus} is related to a qualified certificate
	 *
	 * @param status {@link CertificateQualifiedStatus} to check
	 * @return TRUE if the certificate is qualified, FALSE otherwise
	 */
	public static boolean isQC(CertificateQualifiedStatus status) {
		return QC == status;
	}

}
