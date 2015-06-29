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
package eu.europa.esig.dss.validation;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class holds the list of the candidates for the signing certificate of the main signature.
 */
public class CandidatesForSigningCertificate implements Serializable{

	/**
	 * This field contains the reference to the signing certificate with its validity. This reference is set after the signature verification.
	 */
	private CertificateValidity theCertificateValidity = null;

	/**
	 * This list contains the candidates for the signing certificate.
	 */
	private List<CertificateValidity> certificateValidityList = new ArrayList<CertificateValidity>();

	/**
	 * @return the list of candidates for the signing certificate.
	 */
	public List<CertificateValidity> getCertificateValidityList() {
		return certificateValidityList;
	}

	/**
	 * @return the list of candidates for the signing certificate.
	 */
	public List<CertificateToken> getSigningCertificateTokenList() {

		final List<CertificateToken> signCertificateTokenList = new ArrayList<CertificateToken>();
		for (final CertificateValidity certificateValidity : certificateValidityList) {

			final CertificateToken certificateToken = certificateValidity.getCertificateToken();
			if (certificateToken != null) {
				signCertificateTokenList.add(certificateToken);
			}
		}
		return signCertificateTokenList;
	}

	/**
	 * This method allows to add a candidate for the signing certificate.
	 *
	 * @param certificateValidity A new candidate with its validity.
	 */
	public void add(final CertificateValidity certificateValidity) {
		certificateValidityList.add(certificateValidity);
	}

	/**
	 * This method allows to set the {@code SigningCertificateValidity} object after the verification of its signature. {@code theSigningCertificateValidity} object must be in the
	 * list of the candidates.
	 *
	 * @param theCertificateValidity the certain signing certificate validity object
	 * @throws DSSException if the {@code SigningCertificateValidity} is not present in the list of candidates then the {@code DSSException} is frown.
	 */
	public void setTheCertificateValidity(final CertificateValidity theCertificateValidity) throws DSSException {

		if (theCertificateValidity == null) {
			throw new NullPointerException();
		}
		if (!certificateValidityList.contains(theCertificateValidity)) {
			throw new DSSException("theSigningCertificateValidity must be the part of the candidates!");
		}
		this.theCertificateValidity = theCertificateValidity;
	}

	/**
	 * The {@code theSigningCertificateValidity} object must be set before.
	 *
	 * @return the signing certificate validity {@code SigningCertificateValidity} or {@code null} if such a certificate was not identified.
	 */
	public CertificateValidity getTheCertificateValidity() {
		return theCertificateValidity;
	}

	/**
	 * This method returns the best candidate for the signing certificate. The only way to be sure that it is the right one is to validate the signature.
	 *
	 * @return The valid signing certificate, if there is no valid certificate then the first one is returned.
	 */
	public CertificateValidity getTheBestCandidate() {

		CertificateValidity firstCandidate = null;
		for (final CertificateValidity certificateValidity : certificateValidityList) {

			if (firstCandidate == null) {
				firstCandidate = certificateValidity;
			}
			if (certificateValidity.isValid()) {

				return certificateValidity;
			}
		}
		return firstCandidate;
	}
}
