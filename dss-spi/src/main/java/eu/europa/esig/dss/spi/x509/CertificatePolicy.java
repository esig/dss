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
package eu.europa.esig.dss.spi.x509;

/**
 * The class represents a certificate policy
 *
 */
public class CertificatePolicy {

	/** Certificate policy OID */
	private String oid;

	/** Certificate policy URL */
	private String cpsUrl;

	/**
	 * Gets OID of the certificate policy
	 *
	 * @return {@link String}
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Sets OID of the certificate policy
	 *
	 * @param oid {@link String}
	 */
	public void setOid(String oid) {
		this.oid = oid;
	}

	/**
	 * Gets URL of the certificate policy
	 *
	 * @return {@link String}
	 */
	public String getCpsUrl() {
		return cpsUrl;
	}

	/**
	 * Sets URL of the certificate policy
	 *
	 * @param cpsUrl {@link String}
	 */
	public void setCpsUrl(String cpsUrl) {
		this.cpsUrl = cpsUrl;
	}

}
