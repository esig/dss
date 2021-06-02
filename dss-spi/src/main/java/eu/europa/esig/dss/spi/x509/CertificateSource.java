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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

/**
 * The validation of a certificate requires to access some other certificates from multiple sources (Trusted List, Trust
 * Store, the signature itself). This interface provides an abstraction for accessing a certificate, regardless of the
 * source.
 */
public interface CertificateSource extends Serializable {

	/**
	 * This method allows to manually add any certificate to the source. The type of
	 * the source is automatically set par each specific implementation.
	 *
	 * @param certificate the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	CertificateToken addCertificate(final CertificateToken certificate);

	/**
	 * This method returns the certificate source type associated to the
	 * implementation class.
	 *
	 * @return the certificate origin
	 */
	CertificateSourceType getCertificateSourceType();

	/**
	 * Retrieves the unmodifiable list of all certificate tokens from this source.
	 *
	 * @return all certificates from this source
	 */
	List<CertificateToken> getCertificates();

	/**
	 * This method checks if a given certificate is trusted
	 * 
	 * @param certificateToken the certificate to be tested
	 * @return true if the certificate is trusted
	 */
	boolean isTrusted(CertificateToken certificateToken);

	/**
	 * This method checks if a given certificate is known in the current source
	 * 
	 * @param certificateToken the certificate to be tested
	 * @return true if the certificate is part of the current source
	 */
	boolean isKnown(CertificateToken certificateToken);

	/**
	 * This method returns the Set of certificates with the same subjectDN.
	 *
	 * @param subject the subject to match
	 * @return If no match is found then an empty set is returned.
	 */
	Set<CertificateToken> getBySubject(X500PrincipalHelper subject);

	/**
	 * This method returns the Set of certificates with the
	 * {@code CertificateIdentifier}
	 *
	 * @param signerIdentifier the certificate identifier to match
	 * @return If no match is found then an empty set is returned.
	 */
	Set<CertificateToken> getBySignerIdentifier(SignerIdentifier signerIdentifier);

	/**
	 * This method returns the Set of certificates with the {@code Digest}
	 * 
	 * @param digest the certificate digest to be found
	 * @return the found certificates or an empty Set
	 */
	Set<CertificateToken> getByCertificateDigest(Digest digest);

	/**
	 * This method returns a Set of {@code CertificateToken} with the given
	 * {@code PublicKey}
	 * 
	 * @param publicKey the public key to find
	 * @return a Set of CertificateToken which have the given public key
	 */
	Set<CertificateToken> getByPublicKey(PublicKey publicKey);

	/**
	 * This method returns a Set of {@code CertificateToken} with the given SKI
	 * (SubjectKeyIdentifier (SHA-1 of the PublicKey))
	 * 
	 * @param ski the Subject Key Identifier
	 * @return a Set of CertificateToken which have the given ski
	 */
	Set<CertificateToken> getBySki(byte[] ski);

	/**
	 * Returns Set of {@link CertificateToken}s for the provided {@link CertificateRef}
	 * 
	 * @param certificateRef a {@link CertificateRef}
	 * @return Set of {@link CertificateToken}s
	 */
	Set<CertificateToken> findTokensFromCertRef(CertificateRef certificateRef);

	/**
	 * Returns a list of certificates grouped by their public keys
	 *
	 * @return a list of {@link CertificateSourceEntity}s
	 */
	List<CertificateSourceEntity> getEntities();

	/**
	 * This method checks if all certificates are self-signed
	 * 
	 * @return true if all certificates are self-signed
	 */
	boolean isAllSelfSigned();

	/**
	 * This method checks if the current and the given {@code CertificateSource}s contain the same certificate tokens
	 *
	 * @param certificateSource {@link CertificateSource} to compare
	 * @return TRUE if both certificate sources contains the same certificate tokens, FALSE otherwise
	 */
	boolean isCertificateSourceEqual(CertificateSource certificateSource);

	/**
	 * This method checks if the current and the given {@code CertificateSource}s contain the same public keys
	 *
	 * @param certificateSource {@link CertificateSource} to compare
	 * @return TRUE if both certificate sources contains the same public keys, FALSE otherwise
	 */
	boolean isCertificateSourceEquivalent(CertificateSource certificateSource);

}
