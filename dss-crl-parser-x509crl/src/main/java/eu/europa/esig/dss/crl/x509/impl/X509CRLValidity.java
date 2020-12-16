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
package eu.europa.esig.dss.crl.x509.impl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLValidity;

import java.security.cert.X509CRL;

/**
 * The java.security.cert.X509CRL extension of {@code CRLValidity}
 */
public class X509CRLValidity extends CRLValidity {

	/**
	 * The {@code X509CRL} object
	 */
	private X509CRL x509CRL;
	
	/**
	 * Default constructor
	 *
	 * @param crlBinary {@link CRLBinary}
	 */
	public X509CRLValidity(CRLBinary crlBinary) {
		super(crlBinary);
	}

	/**
	 * Gets the {@code X509CRL}
	 *
	 * @return {@link X509CRL}
	 */
	public X509CRL getX509CRL() {
		return x509CRL;
	}

	/**
	 * Sets the {@code X509CRL}
	 *
	 * @param x509crl {@link X509CRL}
	 */
	public void setX509CRL(X509CRL x509crl) {
		x509CRL = x509crl;
	}

}
