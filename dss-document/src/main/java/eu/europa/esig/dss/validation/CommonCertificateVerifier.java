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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.ListCRLSource;
import eu.europa.esig.dss.x509.ocsp.ListOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

/**
 * This class provides the different sources used to verify the status of a certificate using the trust model. There are four different types of sources to be defined:<br /> -
 * Trusted certificates source;<br /> - Adjunct certificates source (not trusted);<br /> - OCSP source;<br /> - CRL source.<br />
 *
 * The {@code DataLoader} should be provided to give access to the certificates through AIA.
 *
 *
 */

public class CommonCertificateVerifier implements CertificateVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(CommonCertificateVerifier.class);

	/**
	 * This field contains the reference to the trusted certificate source. This source is fixed, it means that the same source is used for different validations.
	 */
	private CertificateSource trustedCertSource;

	/**
	 * This field contains the reference to any certificate source, can contain the trust store, or the any intermediate certificates.
	 */
	private CertificateSource adjunctCertSource;

	/**
	 * This field contains the reference to the {@code OCSPSource}.
	 */
	private OCSPSource ocspSource;

	/**
	 * This field contains the reference to the {@code CRLSource}.
	 */
	private CRLSource crlSource;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * This variable contains the {@code ListCRLSource} extracted from the signatures to validate.
	 */
	private ListCRLSource signatureCRLSource;

	/**
	 * This variable contains the {@code ListOCSPSource} extracted from the signatures to validate.
	 */
	private ListOCSPSource signatureOCSPSource;

	/**
	 * The default constructor. The {@code DataLoader} is created to allow the retrieval of certificates through AIA.
	 */
	public CommonCertificateVerifier() {
		LOG.info("+ New CommonCertificateVerifier created.");
		dataLoader = new NativeHTTPDataLoader();
	}

	/**
	 * This constructor allows to create {@code CommonCertificateVerifier} without {@code DataLoader}. It means that only a profile -B signatures can be created.
	 *
	 * @param simpleCreationOnly if true the {@code CommonCertificateVerifier} will not contain {@code DataLoader}.
	 */
	public CommonCertificateVerifier(final boolean simpleCreationOnly) {
		if (!simpleCreationOnly) {
			dataLoader = new NativeHTTPDataLoader();
		}
	}

	/**
	 * The constructor with key parameters.
	 *
	 * @param trustedCertSource the reference to the trusted certificate source.
	 * @param crlSource         contains the reference to the {@code OCSPSource}.
	 * @param ocspSource        contains the reference to the {@code CRLSource}.
	 * @param dataLoader        contains the reference to a data loader used to access AIA certificate source.
	 */
	public CommonCertificateVerifier(final CertificateSource trustedCertSource, final CRLSource crlSource, final OCSPSource ocspSource, final DataLoader dataLoader) {

		LOG.info("+ New CommonCertificateVerifier created with parameters.");
		this.trustedCertSource = trustedCertSource;
		this.crlSource = crlSource;
		this.ocspSource = ocspSource;
		this.dataLoader = dataLoader;
		if (dataLoader == null) {
			LOG.warn("DataLoader is null. It's required to access AIA certificate source");
		}
	}

	/**
	 * @return
	 */
	@Override
	public CertificateSource getTrustedCertSource() {

		return trustedCertSource;
	}

	/**
	 * @return
	 */
	@Override
	public OCSPSource getOcspSource() {

		return ocspSource;
	}

	/**
	 * @return
	 */
	@Override
	public CRLSource getCrlSource() {

		return crlSource;
	}

	/**
	 * Defines the source of CRL used by this class
	 *
	 * @param crlSource the crlSource to set
	 */
	@Override
	public void setCrlSource(final CRLSource crlSource) {

		this.crlSource = crlSource;
	}

	/**
	 * Defines the source of OCSP used by this class
	 *
	 * @param ocspSource the ocspSource to set
	 */
	@Override
	public void setOcspSource(final OCSPSource ocspSource) {

		this.ocspSource = ocspSource;
	}

	/**
	 * Defines how the certificates from the Trusted Lists are retrieved. This source should provide trusted certificates. These certificates are used as trust anchors.
	 *
	 * @param trustedCertSource The source of trusted certificates.
	 */
	@Override
	public void setTrustedCertSource(final CertificateSource trustedCertSource) {

		this.trustedCertSource = trustedCertSource;
	}

	/**
	 * @return
	 */
	@Override
	public CertificateSource getAdjunctCertSource() {

		return adjunctCertSource;
	}

	/**
	 * @param adjunctCertSource
	 */
	@Override
	public void setAdjunctCertSource(final CertificateSource adjunctCertSource) {

		this.adjunctCertSource = adjunctCertSource;
	}

	@Override
	public DataLoader getDataLoader() {
		return dataLoader;
	}

	@Override
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	@Override
	public ListCRLSource getSignatureCRLSource() {
		return signatureCRLSource;
	}

	@Override
	public void setSignatureCRLSource(final ListCRLSource signatureCRLSource) {

		this.signatureCRLSource = signatureCRLSource;
	}

	@Override
	public ListOCSPSource getSignatureOCSPSource() {
		return signatureOCSPSource;
	}

	@Override
	public void setSignatureOCSPSource(final ListOCSPSource signatureOCSPSource) {

		this.signatureOCSPSource = signatureOCSPSource;
	}

	@Override
	public CertificatePool createValidationPool() {

		final CertificatePool validationPool = new CertificatePool();
		if (trustedCertSource != null) {

			validationPool.merge(trustedCertSource.getCertificatePool());
		}
		if (adjunctCertSource != null) {

			validationPool.merge(adjunctCertSource.getCertificatePool());
		}
		return validationPool;
	}
}
