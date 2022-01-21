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
                LOG.warn("No issuer found for the token creation date. The process continues with an issuer which has the same public key.");
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
                    LOG.info("The issuer subject name and subject name does not match (more details in debug mode).");
                    if (LOG.isDebugEnabled()) {
                        LOG.info("CERT ISSUER    : {}", issuerX500PrincipalHelper.getCanonical());
                        LOG.info("ISSUER SUBJECT : {}", candidate.getSubject().getCanonical());
                    }
                }
            }
        }
        // return provided collection of candidates if no issuers matching the subject name have been found
        return Utils.isCollectionNotEmpty(issuers) ? issuers : candidates;
    }

}
