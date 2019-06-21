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

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;

/**
 * This interface allows the implementation of the validators for: certificates, timestamps and revocation data.
 */
public interface ValidationContext {

	/**
	 * This function sets the validation time.
	 *
	 * @param currentTime
	 *            the current {@code Date}
	 */
	void setCurrentTime(final Date currentTime);

	void initialize(final CertificateVerifier certificateVerifier);

	Date getCurrentTime();

	/**
	 * Adds a list of new revocation tokens to the list of tokens to verify. If the revocation token has already been
	 * added then it is ignored.
	 *
	 * @param revocationTokens
	 *            a list of {@code RevocationToken} revocation tokens to verify
	 */
	void addRevocationTokensForVerification(final List<RevocationToken> revocationTokens);

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
	 * Carries out the validation process in recursive manner for not yet checked tokens.
	 *
	 * @throws DSSException
	 *             if an error occurred
	 */
	void validate() throws DSSException;

	/**
	 * This method allows to verify if all processed certificates have a revocation
	 * data
	 * 
	 * @return true if at least one revocation data is present for each certificate
	 * 
	 */
	boolean isAllRequiredRevocationDataPresent();

	/**
	 * This method allows to verify if all POE (timestamp tokens) are covered by a
	 * revocation data
	 * 
	 * @return true if all POE have at least one revocation data issued after the
	 *         POE creation
	 * 
	 */
	boolean isAllPOECoveredByRevocationData();

	/**
	 * This method allows to verify if all processed timestamps are valid and intact
	 * 
	 * @return true if all processed timestamps are valid
	 */
	boolean isAllTimestampValid();

	/**
	 * This method allows to verify if all processed certificates are not revoked
	 * 
	 * @return true if all processed certificates are still valid
	 */
	boolean isAllCertificateValid();

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
	Set<RevocationToken> getProcessedRevocations();

	/**
	 * Returns a read only list of all timestamps processed during the validation of all signatures from the given
	 * document.
	 *
	 * @return The list of CertificateToken(s)
	 */
	Set<TimestampToken> getProcessedTimestamps();

}
