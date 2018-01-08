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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@SuppressWarnings("serial")
public class TokenValidationExtraInfo implements Serializable {

	/*
	 * This is the list of text messages created during the signature validation process. It allows to get more
	 * information about different problems encountered during the curse of this process.
	 */
	private List<String> validationInfo = new ArrayList<String>();

	/**
	 * Returns the additional information gathered during the validation process.
	 *
	 * @return additional validation information
	 */
	public List<String> getValidationInfo() {
		return Collections.unmodifiableList(validationInfo);
	}

	/**
	 * This method add an information as the issuer/signing certificate is not found
	 */
	public void infoTheSigningCertNotFound() {
		addInfo("The certificate used to sign this token is not found or not valid!");
	}

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
	 * 
	 * @param message
	 *            the exception message
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
	 * 
	 * @param message
	 *            the exception message
	 */
	public void infoCRLException(final String message) {
		addInfo("An exception occurred during the CRL retrieval process : " + message);
	}

	/**
	 * This method adds an information as the extension 'id-pkix-ocsp-nocheck' is in the certificate
	 */
	public void infoOCSPNoCheckPresent() {
		addInfo("OCSP check not needed: id-pkix-ocsp-nocheck extension present.");
	}

	/**
	 * This method adds the message to the information list
	 * 
	 * @param message
	 *            the message to be added
	 */
	private void addInfo(String message) {
		validationInfo.add(message);
	}

}
