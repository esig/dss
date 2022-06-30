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
package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.util.List;

/**
 * Contains certificates for the url location
 */
public class OtherTSLPointer implements Serializable {

	private static final long serialVersionUID = 3015076999802292662L;

	/** URL location */
	private final String location;

	/** List of certificates */
	private final List<CertificateToken> certificates;

	private final MRA mra;

	/**
	 * Default constructor
	 *
	 * @param location {@link String} url
	 * @param certificates list of {@link CertificateToken}s
	 */
	public OtherTSLPointer(String location, List<CertificateToken> certificates, MRA mra) {
		this.location = location;
		this.certificates = certificates;
		this.mra = mra;
	}

	/**
	 * Gets location url
	 *
	 * @return {@link String}
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * Gets a list of certificates
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public MRA getMra() {
		return mra;
	}

}
