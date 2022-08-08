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

import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Contains a validation data to be included into the signature
 */
public class ValidationData {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationData.class);

	/** Set of certificate tokens */
	private final Set<CertificateToken> certificateTokens = new HashSet<>();

	/** List of CRL tokens */
	private final Set<CRLToken> crlTokens = new HashSet<>();

	/** List of OCSP tokens */
	private final Set<OCSPToken> ocspTokens = new HashSet<>();

	/** Internal set of containing public keys */
	private final Set<EntityIdentifier> storedPublicKeys = new HashSet<>();

	/**
	 * Default constructor instantiating empty maps of tokens
	 */
	public ValidationData() {
		// empty
	}

	/**
	 * Gets certificate tokens to be included into the signature
	 *
	 * @return a set of {@link CertificateToken}s
	 */
	public Set<CertificateToken> getCertificateTokens() {
		return Collections.unmodifiableSet(certificateTokens);
	}

	/**
	 * Sets CRL tokens to be included into the signature
	 *
	 * @return a list of {@link CRLToken}s
	 */
	public Set<CRLToken> getCrlTokens() {
		return Collections.unmodifiableSet(crlTokens);
	}

	/**
	 * Sets OCSP tokens to be included into the signature
	 *
	 * @return a list of {@link OCSPToken}s
	 */
	public Set<OCSPToken> getOcspTokens() {
		return Collections.unmodifiableSet(ocspTokens);
	}

	/**
	 * Adds validation data token and boolean indication if the token has been added successfully
	 *
	 * @param token {@link Token} token to be added
	 * @return TRUE of the given token has been added successfully to the ValidationData, FALSE otherwise
	 */
	public boolean addToken(final Token token) {
		if (token instanceof CertificateToken) {
			if (addCertificateToken((CertificateToken) token)) {
				return true;
			}

		} else if (token instanceof RevocationToken) {
			if (addRevocationToken((RevocationToken<?>) token)) {
				return true;
			}

		} else {
			throw new DSSException(String.format("Unexpected token with Id '%s'", token.getDSSIdAsString()));
		}

		LOG.trace("ValidationData instance already contains token with Id '{}'",
				token.getDSSIdAsString());
		return false;
	}

	private boolean addCertificateToken(final CertificateToken certificateToken) {
		if (!containsCertificateToken(certificateToken)) {
			boolean added = certificateTokens.add(certificateToken);
			if (added) {
				storedPublicKeys.add(certificateToken.getEntityKey());
				LOG.trace("CertificateToken with Id '{}' has been added to the ValidationData instance",
						certificateToken.getDSSIdAsString());
				return true;
			}
		}
		return false;
	}

	private boolean addRevocationToken(final RevocationToken<?> revocationToken) {
		if (RevocationType.CRL.equals(revocationToken.getRevocationType())) {
			CRLToken crlToken = (CRLToken) revocationToken;
			if (!containsCRLToken(crlToken)) {
				boolean added = crlTokens.add(crlToken);
				if (added) {
					LOG.trace("CRL RevocationToken with Id '{}' has been added to the ValidationData instance",
							revocationToken.getDSSIdAsString());
					return true;
				}
			}

		} else if (RevocationType.OCSP.equals(revocationToken.getRevocationType())) {
			OCSPToken ocspToken = (OCSPToken) revocationToken;
			if (!containsOCSPToken(ocspToken)) {
				boolean added = ocspTokens.add(ocspToken);
				if (added) {
					LOG.trace("OCSP RevocationToken with Id '{}' has been added to the ValidationData instance",
							revocationToken.getDSSIdAsString());
					return true;
				}
			}

		} else {
			throw new DSSException(String.format("Unexpected RevocationToken with Id '%s'", revocationToken.getDSSIdAsString()));
		}
		return false;
	}

	private boolean containsCertificateToken(CertificateToken certificateTokenToAdd) {
		return certificateTokens.contains(certificateTokenToAdd) || storedPublicKeys.contains(certificateTokenToAdd.getEntityKey());
	}

	private boolean containsCRLToken(CRLToken crlTokenToAdd) {
		for (CRLToken crlToken : crlTokens) {
			if (crlTokenToAdd.getDSSIdAsString().equals(crlToken.getDSSIdAsString())) {
				return true;
			}
		}
		return false;
	}

	private boolean containsOCSPToken(OCSPToken ocspTokenToAdd) {
		for (OCSPToken ocspToken : ocspTokens) {
			if (ocspTokenToAdd.getDSSIdAsString().equals(ocspToken.getDSSIdAsString())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Allows to add all tokens from a provided validation data to the current collection
	 *
	 * @param validationData {@link ValidationData} to add tokens from
	 */
	public void addValidationData(final ValidationData validationData) {
		for (Token token : validationData.getCertificateTokens()) {
			addToken(token);
		}
		for (Token token : validationData.getCrlTokens()) {
			addToken(token);
		}
		for (Token token : validationData.getOcspTokens()) {
			addToken(token);
		}
	}

	/**
	 * Removes all certificate token entries matching the provided collection
	 *
	 * @param certificateTokensToExclude a collection of {@link CertificateToken} to exclude
	 */
	public void excludeCertificateTokens(Collection<CertificateToken> certificateTokensToExclude) {
		if (Utils.isCollectionNotEmpty(certificateTokensToExclude)) {
			for (CertificateToken certificateToken : certificateTokensToExclude) {
				if (containsCertificateToken(certificateToken)) {
					storedPublicKeys.remove(certificateToken.getEntityKey());
					excludeWithEntityKey(certificateToken.getEntityKey());
				}
			}
		}
	}

	private void excludeWithEntityKey(EntityIdentifier entityIdentifier) {
		certificateTokens.removeIf(certToken -> entityIdentifier.equals(certToken.getEntityKey()));
	}

	/**
	 * Removes all CRL token entries matching the provided collection of encapsulated CRL binaries
	 *
	 * @param crlTokensToExclude a collection of {@link EncapsulatedRevocationTokenIdentifier} to exclude
	 */
	public void excludeCRLTokens(Collection<EncapsulatedRevocationTokenIdentifier<CRL>> crlTokensToExclude) {
		if (Utils.isCollectionNotEmpty(crlTokensToExclude)) {
			Set<String> tokenIdsToExclude = crlTokensToExclude.stream().map(c -> c.getDSSId().asXmlId()).collect(Collectors.toSet());
			crlTokens.removeIf(crlToken -> tokenIdsToExclude.contains(crlToken.getDSSIdAsString()));
		}
	}

	/**
	 * Removes all OCSP token entries matching the provided collection of encapsulated OCSP binaries
	 *
	 * @param ocspTokensToExclude a collection of {@link EncapsulatedRevocationTokenIdentifier} to exclude
	 */
	public void excludeOCSPTokens(Collection<EncapsulatedRevocationTokenIdentifier<OCSP>> ocspTokensToExclude) {
		if (Utils.isCollectionNotEmpty(ocspTokensToExclude)) {
			Set<String> tokenIdsToExclude = ocspTokensToExclude.stream().map(c -> c.getDSSId().asXmlId()).collect(Collectors.toSet());
			ocspTokens.removeIf(ocspToken -> tokenIdsToExclude.contains(ocspToken.getDSSIdAsString()));
		}
	}

	/**
	 * Checks if the validation data is empty
	 *
	 * @return TRUE if the object is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return Utils.isCollectionEmpty(certificateTokens) && Utils.isCollectionEmpty(crlTokens)
				&& Utils.isCollectionEmpty(ocspTokens);
	}

}
