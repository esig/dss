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
package eu.europa.esig.dss.x509;

import java.util.Date;

import eu.europa.esig.dss.DSSUtils;

public class CertificateTokenValidationExtraInfo extends TokenValidationExtraInfo {

	/**
	 * This method adds an information as OCSP source is null
	 */
	public void infoOCSPSourceIsNull() {
		addInfo("The OCSP source is null !");
	}

	/**
	 * This method adds an information as no OCSP URI found
	 */
	public void infoNoOcspUriFoundInCertificate() {
		addInfo("OSCP Uri not found in certificate meta-data !");
	}

	/**
	 * This method allows to add an exception message with OCSP
	 */
	public void infoOCSPException(final String message) {
		addInfo("An exception occurred during the OCSP retrieval process : " + message);
	}

	/**
	 * This method adds an information as CRL source is null
	 */
	public void infoCRLSourceIsNull() {
		addInfo("The CRL source is null!");
	}

	/**
	 * This method adds an information as CRL not found
	 */
	public void infoNoCRLInfoFound() {
		addInfo("No CRL info found !");
	}

	/**
	 * This method adds an information as invalid CRL
	 */
	public void infoCRLIsNotValid() {
		addInfo("The CRL is not valid!");
	}

	/**
	 * This method allows to add an exception message with CRL
	 */
	public void infoCRLException(final String message) {
		addInfo("An exception occurred during the CRL retrieval process : " + message);
	}

	public void infoTheCertNotValidYet(final Date validationDate, final Date notAfter, final Date notBefore) {
		final String endDate = DSSUtils.formatInternal(notAfter);
		final String startDate = DSSUtils.formatInternal(notBefore);
		final String valDate = DSSUtils.formatInternal(validationDate);
		addInfo("The certificate is not valid yet! [" + startDate + "-" + endDate + "] on " + valDate);
	}

	public void infoTheCertIsExpired(final Date validationDate, final Date notAfter, final Date notBefore) {
		final String endDate = DSSUtils.formatInternal(notAfter);
		final String startDate = DSSUtils.formatInternal(notBefore);
		final String valDate = DSSUtils.formatInternal(validationDate);
		addInfo("The certificate is expired! [" + startDate + "-" + endDate + "] on " + valDate);
	}

}
