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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Date;
import java.util.Set;

/**
 * This interface allows the implementation of the validators for: certificates, timestamps and revocation data.
 */
public interface ValidationContext {

	/**
	 * This method initializes the {@code ValidationContext} by retrieving the relevant data
	 * from {@code certificateVerifier}
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	void initialize(final CertificateVerifier certificateVerifier);

	/**
	 * This function sets the validation time.
	 *
	 * @param currentTime
	 *            the current {@code Date}
	 */
	void setCurrentTime(final Date currentTime);

	/**
	 * Gets the current validation time.
	 *
	 * @return {@link Date}
	 */
	Date getCurrentTime();

	/**
	 * Adds a new signature to collect the information to verify.
	 *
	 * @param signature {@link AdvancedSignature} to extract data to be verified
	 */
	void addSignatureForVerification(final AdvancedSignature signature);

	/**
	 * Adds a new revocation token to the list of tokens to verify. If the
	 * revocation token has already been added then it is ignored.
	 *
	 * @param revocationToken an instance of {@code RevocationToken} revocation
	 *                        tokens to verify
	 */
	void addRevocationTokenForVerification(final RevocationToken<?> revocationToken);

	/**
	 * Adds a new certificate token to the list of tokens to verify. If the certificate token has already been added
	 * then it is ignored.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken} certificate token to verify
	 */
	void addCertificateTokenForVerification(final CertificateToken certificateToken);

	/**
	 * Adds a new timestamp token to the list of tokens to verify. If the timestamp token has already been added then it
	 * is ignored.
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} timestamp token to verify
	 */
	void addTimestampTokenForVerification(final TimestampToken timestampToken);


	/**
	 * Adds an extracted certificate source to the used list of sources
	 *
	 * @param certificateSource {@link CertificateSource}
	 */
	void addDocumentCertificateSource(CertificateSource certificateSource);


	/**
	 * Adds a list certificate source to the used list of sources
	 *
	 * @param listCertificateSource {@link ListCertificateSource}
	 */
	void addDocumentCertificateSource(ListCertificateSource listCertificateSource);

	/**
	 * Adds an extracted CRL source to the used list of sources
	 *
	 * @param crlSource {@link OfflineRevocationSource} for CRL
	 */
	void addDocumentCRLSource(OfflineRevocationSource<CRL> crlSource);

	/**
	 * Adds a list CRL source to the used list of sources
	 *
	 * @param crlSource {@link ListRevocationSource} for CRL
	 */
	void addDocumentCRLSource(ListRevocationSource<CRL> crlSource);

	/**
	 * Adds an extracted OCSP source to the used list of sources
	 *
	 * @param ocspSource {@link OfflineRevocationSource} for OCSP
	 */
	void addDocumentOCSPSource(OfflineRevocationSource<OCSP> ocspSource);

	/**
	 * Adds a listd OCSP source to the used list of sources
	 *
	 * @param ocspSource {@link ListRevocationSource} for OCSP
	 */
	void addDocumentOCSPSource(ListRevocationSource<OCSP> ocspSource);

	/**
	 * Carries out the validation process in recursive manner for not yet checked
	 * tokens.
	 */
	void validate();

	/**
	 * This method allows to verify if all processed certificates have a revocation
	 * data
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnMissingRevocationData(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @return true if all needed revocation data are present
	 */
	boolean checkAllRequiredRevocationDataPresent();

	/**
	 * This method allows to verify if all POE (timestamp tokens) are covered by a
	 * revocation data
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnUncoveredPOE(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @return true if all timestamps are covered by a usable revocation data
	 */
	boolean checkAllPOECoveredByRevocationData();

	/**
	 * This method allows to verify if all processed timestamps are valid and
	 * intact.
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnInvalidTimestamp(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @return true if all timestamps are valid
	 */
	boolean checkAllTimestampsValid();

	/**
	 * This method allows to verify if the certificate is not revoked
	 *
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnRevokedCertificate(eu.europa.esig.dss.alert.StatusAlert)}
	 *
	 * @param certificateToken {@code CertificateToken} certificate to be checked
	 * @return true if all certificates are valid
	 */
	boolean checkCertificateNotRevoked(CertificateToken certificateToken);

	/**
	 * This method allows to verify if signature certificates are not revoked
	 *
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnRevokedCertificate(eu.europa.esig.dss.alert.StatusAlert)}
	 *
	 * @param signature {@code AdvancedSignature} signature to be checked
	 * @return true if all certificates are valid
	 */
	boolean checkCertificatesNotRevoked(AdvancedSignature signature);

	/**
	 * This method allows to verify if there is at least one revocation data present
	 * after the earliest available timestamp token producing time
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnNoRevocationAfterBestSignatureTime(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @param signature {@code AdvancedSignature} signature to be checked
	 * @return true if the signing certificate is covered with a updated revocation
	 *         data (after signature-timestamp production time)
	 * 
	 */
	boolean checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(AdvancedSignature signature);

	/**
	 * This method verifies if the signing certificate has not been expired yet or has a still valid timestamp
	 *
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnExpiredSignature(eu.europa.esig.dss.alert.StatusAlert)}
	 *
	 * @param signature {@code AdvancedSignature} signature to be verified
	 * @return true if the signing certificate or its POE(s) not yet expired, false otherwise
	 *
	 */
	boolean checkSignatureNotExpired(AdvancedSignature signature);

	/**
	 * Returns a read only list of all certificates used in the process of the validation of all signatures from the
	 * given document. This list
	 * includes the certificate to check, certification chain certificates, OCSP response certificate...
	 *
	 * @return The list of CertificateToken(s)
	 */
	Set<CertificateToken> getProcessedCertificates();

	/**
	 * Returns a read only list of all revocations used in the process of the validation of all signatures from the
	 * given document.
	 *
	 * @return The list of RevocationToken(s)
	 */
	Set<RevocationToken> getProcessedRevocations();

	/**
	 * Returns a read only list of all timestamps processed during the validation of all signatures from the given
	 * document.
	 *
	 * @return The list of TimestampTokens(s)
	 */
	Set<TimestampToken> getProcessedTimestamps();

	/**
	 * Returns a list of all {@code CertificateSource}s used during the validation process.
	 * It is represented by sources extracted from the provided document (e.g. signatures, timestamps)
	 * as well as the sources obtained during the validation process (e.g. AIA, OCSP).
	 *
	 * @return {@link ListCertificateSource}
	 */
	ListCertificateSource getAllCertificateSources();

	/**
	 * Returns a list of all {@code CertificateSource}s extracted from a validating document (signature(s), timestamp(s))
	 *
	 * @return {@link ListCertificateSource}
	 */
	ListCertificateSource getDocumentCertificateSource();

	/**
	 * Returns a list of all CRL {@code OfflineRevocationSource}s extracted from a validating document
	 *
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<CRL> getDocumentCRLSource();

	/**
	 * Returns a list of all OCSP {@code OfflineRevocationSource}s extracted from a validating document
	 *
	 * @return {@link ListRevocationSource}
	 */
	ListRevocationSource<OCSP> getDocumentOCSPSource();

	/**
	 * Returns a validation data for the given signature's certificate chain
	 *
	 * @param signature {@link AdvancedSignature} to extract validation data for
	 * @return {@link ValidationData}
	 */
	ValidationData getValidationData(final AdvancedSignature signature);

	/**
	 * Returns a validation data for the given timestampToken's certificate chain
	 *
	 * @param timestampToken {@link TimestampToken} to extract validation data for
	 * @return {@link ValidationData}
	 */
	ValidationData getValidationData(final TimestampToken timestampToken);

}
