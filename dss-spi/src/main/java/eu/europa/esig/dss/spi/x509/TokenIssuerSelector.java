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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * This class is used to select an issuer of the provided {@code Token}
 *
 */
public class TokenIssuerSelector {

    private static final Logger LOG = LoggerFactory.getLogger(TokenIssuerSelector.class);

    /** The token to get an issuer for */
    private final Token token;

    /** Collection of issuer candidates */
    private final Collection<CertificateToken> certificateTokens;

    /**
     * Default constructor
     *
     * @param token {@link Token} to get an issuer for
     * @param certificateTokens collection of {@link CertificateToken}s representing {@code token} issuer candidates
     */
    public TokenIssuerSelector(final Token token, final Collection<CertificateToken> certificateTokens) {
        this.token = token;
        this.certificateTokens = certificateTokens;
    }

    /**
     * Filters {@code certificateTokens} and returns the best issuer candidate for {@code token}
     *
     * @return {@link CertificateToken} issuing the {@code token} if found, null otherwise
     */
    public CertificateToken getIssuer() {
        if (Utils.isCollectionNotEmpty(certificateTokens)) {
            Collection<CertificateToken> candidates = filterIssuersByPublicKey(token, certificateTokens);
            candidates = filterIssuersByIssuerSubjectName(token, candidates);

            for (CertificateToken candidate : candidates) {
                if (candidate.isValidOn(token.getCreationDate())) {
                    return candidate;
                }
            }
            if (Utils.isCollectionNotEmpty(candidates)) {
                LOG.warn("No matching issuer found for the token creation date. " +
                        "The process continues with an issuer which has the same public key.");
                return candidates.iterator().next();
            }
        }
        return null;
    }

    /**
     * This method filters a collection of {@code candidates} having a public key
     * matching the one used to sign {@code token}
     *
     * @param token {@link Token} to get issuers for
     * @param candidates a collection of {@link CertificateToken}s
     * @return a collection of {@code CertificateToken}s issuer candidates
     */
    private static Collection<CertificateToken> filterIssuersByPublicKey(Token token, Collection<CertificateToken> candidates) {
        List<CertificateToken> issuers = new ArrayList<>();
        for (CertificateToken candidate : candidates) {
            if (token.isSignedBy(candidate)) {
                issuers.add(candidate);
            }
        }
        return issuers;
    }

    /**
     * Filters a collection of {@code candidates} with a Subject name matching
     * the Issuer Subject name of the {@code token}.
     * In case none of the certificates matching the Issuer Subject name found across {@code candidates},
     * returns the original collection of {@code candidates}.
     *
     * @param token {@link Token} to get issuers for
     * @param candidates a collection of {@link CertificateToken}s
     * @return a collection of {@code CertificateToken}s issuer candidates
     */
    private static Collection<CertificateToken> filterIssuersByIssuerSubjectName(Token token, Collection<CertificateToken> candidates) {
        List<CertificateToken> issuers = new ArrayList<>();
        X500Principal issuerX500Principal = token.getIssuerX500Principal();
        if (issuerX500Principal != null) {
            X500PrincipalHelper issuerX500PrincipalHelper = new X500PrincipalHelper(issuerX500Principal);
            for (CertificateToken candidate : candidates) {
                if (issuerX500PrincipalHelper.equals(candidate.getSubject())) {
                    issuers.add(candidate);
                } else {
                    LOG.warn("The issuer subject name and subject name do not match (more details in debug mode).");
                    if (LOG.isDebugEnabled()) {
                        LOG.info("CERT ISSUER    : {}. Base64 : {}", issuerX500PrincipalHelper.getCanonical(), Utils.toBase64(issuerX500PrincipalHelper.getEncoded()));
                        LOG.info("ISSUER SUBJECT : {}. Base64 : {}", candidate.getSubject().getCanonical(), Utils.toBase64(candidate.getSubject().getEncoded()));
                    }
                }
            }
        }
        // return provided collection of candidates if no issuers matching the subject name have been found
        return Utils.isCollectionNotEmpty(issuers) ? issuers : candidates;
    }

}
