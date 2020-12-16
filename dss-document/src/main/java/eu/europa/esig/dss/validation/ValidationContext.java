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

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Date;
import java.util.Map;
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
	 * Adds a new revocation token to the list of tokens to verify. If the
	 * revocation token has already been added then it is ignored.
	 *
	 * @param revocationToken an instance of {@code RevocationToken} revocation
	 *                        tokens to verify
	 */
	void addRevocationTokenForVerification(final RevocationToken<Revocation> revocationToken);

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
	 * This method allows to verify if all processed certificates are not revoked
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnRevokedCertificate(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @return true if all certificates are valid
	 */
	boolean checkAllCertificatesValid();

	/**
	 * This method allows to verify if there is at least one revocation data present
	 * after the earliest available timestamp token producing time
	 * 
	 * Additionally, an alert can be handled
	 * {@link CertificateVerifier#setAlertOnNoRevocationAfterBestSignatureTime(eu.europa.esig.dss.alert.StatusAlert)}
	 * 
	 * @param signingCertificate {@code CertificateToken} signing certificate of the
	 *                           signature to be checked
	 * @return true if the signing certificate is covered with a updated revocation
	 *         data (after signature-timestamp production time)
	 * 
	 */
	boolean checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(CertificateToken signingCertificate);

	/**
	 * Returns a read only list of all certificates used in the process of the validation of all signatures from the
	 * given document. This list
	 * includes the certificate to check, certification chain certificates, OCSP response certificate...
	 *
	 * @return The list of CertificateToken(s)
	 */
	Set<CertificateToken> getProcessedCertificates();

	/**
	 * Returns a map of {@code CertificateSourceType} by {@code CertificateToken}
	 * which contains the sources where the certificate was found.
	 * 
	 * @return a map of CertificateSourceType by CertificateToken
	 */
	Map<CertificateToken, Set<CertificateSourceType>> getCertificateSourceTypes();

	/**
	 * Returns a read only list of all revocations used in the process of the validation of all signatures from the
	 * given document.
	 *
	 * @return The list of CertificateToken(s)
	 */
	Set<RevocationToken<Revocation>> getProcessedRevocations();

	/**
	 * Returns a read only list of all timestamps processed during the validation of all signatures from the given
	 * document.
	 *
	 * @return The list of CertificateToken(s)
	 */
	Set<TimestampToken> getProcessedTimestamps();

}
