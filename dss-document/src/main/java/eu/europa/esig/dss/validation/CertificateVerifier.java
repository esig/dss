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
 */
public interface CertificateVerifier {

	/**
	 * Returns the OCSP source associated with this verifier.
	 *
	 * @return the used OCSP source for external access (web, filesystem,
	 *         cached,...)
	 */
	OCSPSource getOcspSource();

	/**
	 * Returns the CRL source associated with this verifier.
	 *
	 * @return the used CRL source for external access (web, filesystem, cached,...)
	 */
	CRLSource getCrlSource();

	/**
	 * Defines the source of CRL used by this class
	 *
	 * @param crlSource
	 *                  the CRL source to set for external access (web, filesystem,
	 *                  cached,...)
	 */
	void setCrlSource(final CRLSource crlSource);

	/**
	 * Defines the source of OCSP used by this class
	 *
	 * @param ocspSource
	 *                   the OCSP source to set for external access (web,
	 *                   filesystem, cached,...)
	 */
	void setOcspSource(final OCSPSource ocspSource);

	/**
	 * Returns the trusted certificates source associated with this verifier. This
	 * source is used to identify the trusted anchors.
	 *
	 * @return the certificate source which contains trusted certificates
	 */
	CertificateSource getTrustedCertSource();

	/**
	 * Sets the trusted certificates source.
	 *
	 * @param certSource
	 *                   The certificates source with known trusted certificates
	 */
	void setTrustedCertSource(final CertificateSource certSource);

	/**
	 * Returns the adjunct certificates source associated with this verifier.
	 *
	 * @return the certificate source which contains additional certificate (missing
	 *         CA,...)
	 */
	CertificateSource getAdjunctCertSource();

	/**
	 * Associates an adjunct certificates source to this verifier.
	 *
	 * @param adjunctCertSource
	 *                          the certificate source with additional and missing
	 *                          certificates
	 */
	void setAdjunctCertSource(final CertificateSource adjunctCertSource);

	/**
	 * The data loader used to access AIA certificate source.
	 *
	 * @return the used data loaded to load AIA resources and policy files
	 */
	DataLoader getDataLoader();

	/**
	 * The data loader used to access AIA certificate source. If this property is
	 * not set the default {@code CommonsHttpDataLoader} is created.
	 *
	 * @param dataLoader
	 *                   the used data loaded to load AIA resources and policy files
	 */
	void setDataLoader(final DataLoader dataLoader);

	/**
	 * This method returns the CRL source (information extracted from signatures).
	 * 
	 * @return the CRL sources from the signature
	 */
	ListCRLSource getSignatureCRLSource();

	/**
	 * This method allows to set the CRL source (information extracted from
	 * signatures).
	 *
	 * @param signatureCRLSource
	 *                           the CRL sources from the signature
	 */
	void setSignatureCRLSource(final ListCRLSource signatureCRLSource);

	/**
	 * This method returns the OCSP source (information extracted from signatures).
	 * 
	 * @return the OCSP sources from the signature
	 */
	ListOCSPSource getSignatureOCSPSource();

	/**
	 * This method allows to set the OCSP source (information extracted from
	 * signatures).
	 *
	 * @param signatureOCSPSource
	 *                            the OCSP sources from the signature
	 */
	void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource);

	/**
	 * This method allows to change the behavior on missing revocation data (LT/LTA
	 * augmentation). (default : true)
	 * 
	 * @param throwExceptionOnMissingRevocationData
	 *                                              true if an exception is raised
	 *                                              on missing revocation data,
	 *                                              false will only display a
	 *                                              warning message
	 */
	void setExceptionOnMissingRevocationData(boolean throwExceptionOnMissingRevocationData);

	/**
	 * This method returns true if an exception needs to be thrown on missing
	 * revocation data.
	 * 
	 * @return true if an exception is thrown, false if a warning message is added
	 */
	boolean isExceptionOnMissingRevocationData();

	/**
	 * This method allows to enable revocation checking for untrusted certificate
	 * chains (default : false)
	 * 
	 * @param enable
	 *               true if revocation checking is allowed for untrusted
	 *               certificate chains
	 */
	void setCheckRevocationForUntrustedChains(boolean enable);

	/**
	 * This method returns true if revocation check is enabled for untrusted
	 * certificate chains.
	 * 
	 * @return true if external revocation check is done for untrusted certificate
	 *         chains
	 */
	boolean isCheckRevocationForUntrustedChains();

	/**
	 * This method creates the validation pool of certificates which is used
	 * during the validation process.
	 */
	CertificatePool createValidationPool();

}