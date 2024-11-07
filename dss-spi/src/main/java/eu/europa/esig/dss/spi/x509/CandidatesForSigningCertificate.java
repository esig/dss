/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.DSSException;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class holds the list of the candidates for the signing certificate of the main signature.
 */
public class CandidatesForSigningCertificate implements Serializable {

	private static final long serialVersionUID = 7965288455045066076L;

	/**
	 * This field contains the reference to the signing certificate with its validity. This reference is set after the
	 * signature verification.
	 */
	private CertificateValidity theCertificateValidity = null;

	/**
	 * This list contains the candidates for the signing certificate.
	 */
	private List<CertificateValidity> certificateValidityList = new ArrayList<>();

	/**
	 * Default constructor with null or empty values
	 */
	public CandidatesForSigningCertificate() {
		// empty
	}

	/**
	 * Gets a certificate validity list
	 *
	 * @return the list of candidates for the signing certificate.
	 */
	public List<CertificateValidity> getCertificateValidityList() {
		return certificateValidityList;
	}

	/**
	 * This method tests if any candidate is known
	 * 
	 * @return true is no candidate is known
	 */
	public boolean isEmpty() {
		return certificateValidityList.isEmpty();
	}

	/**
	 * This method allows to add a candidate for the signing certificate.
	 *
	 * @param certificateValidity
	 *            A new candidate with its validity.
	 */
	public void add(final CertificateValidity certificateValidity) {
		certificateValidityList.add(certificateValidity);
	}

	/**
	 * This method allows to set the {@code SigningCertificateValidity} object after the verification of its signature.
	 * {@code theSigningCertificateValidity} object must be in the
	 * list of the candidates.
	 *
	 * @param theCertificateValidity
	 *            the certain signing certificate validity object
	 */
	public void setTheCertificateValidity(final CertificateValidity theCertificateValidity) {
		Objects.requireNonNull(theCertificateValidity, "The CertificateValidity cannot be null");
		if (!certificateValidityList.contains(theCertificateValidity)) {
			throw new DSSException("theSigningCertificateValidity must be the part of the candidates!");
		}
		this.theCertificateValidity = theCertificateValidity;
	}

	/**
	 * The {@code theSigningCertificateValidity} object must be set before.
	 *
	 * @return the signing certificate validity {@code SigningCertificateValidity} or {@code null} if such a certificate
	 *         was not identified.
	 */
	public CertificateValidity getTheCertificateValidity() {
		return theCertificateValidity;
	}

	/**
	 * This method returns the best candidate for the signing certificate. The only way to be sure that it is the right
	 * one is to validate the signature.
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

		CertificateValidity signerIdMatchCandidate = getBySignerIdMatch();
		if (signerIdMatchCandidate != null) {
			return signerIdMatchCandidate;
		}

		if (theCertificateValidity != null) {
			return theCertificateValidity;
		}
		return firstCandidate;
	}

	/**
	 * This method returns the signing certificate which was identified with the CMS SID
	 */
	private CertificateValidity getBySignerIdMatch() {
		for (final CertificateValidity certificateValidity : certificateValidityList) {
			if (certificateValidity.isSignerIdMatch()) {
				return certificateValidity;
			}
		}
		return null;
	}
}
