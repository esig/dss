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

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * Provides information on the sources to be used in the validation process in
 * the context of a signature.
 *
 */
public interface CertificateVerifier {

	/**
	 * Returns the OCSP source associated with this verifier.
	 *
	 * @return
	 */
	OCSPSource getOcspSource();

	/**
	 * Returns the CRL source associated with this verifier.
	 *
	 * @return
	 */
	CRLSource getCrlSource();

	/**
	 * Defines the source of CRL used by this class
	 *
	 * @param crlSource
	 *            the crlSource to set
	 */
	void setCrlSource(final CRLSource crlSource);

	/**
	 * Defines the source of OCSP used by this class
	 *
	 * @param ocspSource
	 *            the ocspSource to set
	 */
	void setOcspSource(final OCSPSource ocspSource);

	/**
	 * Returns the trusted certificates source associated with this verifier.
	 * This source is used to identify the trusted anchor.
	 *
	 * @return
	 */
	CertificateSource getTrustedCertSource();

	/**
	 * Sets the trusted certificates source.
	 *
	 * @param certSource
	 *            The certificates source to set
	 */
	void setTrustedCertSource(final CertificateSource certSource);

	/**
	 * Returns the adjunct certificates source associated with this verifier.
	 *
	 * @return
	 */
	CertificateSource getAdjunctCertSource();

	/**
	 * Associates an adjunct certificates source to this verifier.
	 *
	 * @param adjunctCertSource
	 */
	void setAdjunctCertSource(final CertificateSource adjunctCertSource);

	/**
	 * The data loader used to access AIA certificate source.
	 *
	 * @return
	 */
	DataLoader getDataLoader();

	/**
	 * The data loader used to access AIA certificate source. If this property
	 * is not set the default {@code CommonsHttpDataLoader} is created.
	 *
	 * @param dataLoader
	 */
	void setDataLoader(final DataLoader dataLoader);

	/**
	 * This method returns the CRL source (information extracted from
	 * signatures).
	 */
	ListCRLSource getSignatureCRLSource();

	/**
	 * This method allows to set the CRL source (information extracted from
	 * signatures).
	 *
	 * @param signatureCRLSource
	 */
	void setSignatureCRLSource(final ListCRLSource signatureCRLSource);

	/**
	 * This method returns the OCSP source (information extracted from
	 * signatures).
	 */
	ListOCSPSource getSignatureOCSPSource();

	/**
	 * This method allows to set the OCSP source (information extracted from
	 * signatures).
	 *
	 * @param signatureOCSPSource
	 */
	void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource);

	/**
	 * This method creates the validation pool of certificates which is used
	 * during the validation process.
	 */
	CertificatePool createValidationPool();

}