package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;

import java.util.Date;

/**
 * This class is used to validate the use of cryptographic constraints within the token's certificate chain
 *
 */
public class TokenCertificateChainCryptographicChecker extends CertificateChainCryptographicChecker {

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translations
     */
    public TokenCertificateChainCryptographicChecker(final I18nProvider i18nProvider,
                                                        final TokenProxy token, final Date validationTime,
                                                        final Context context, final MessageTag position, final ValidationPolicy validationPolicy) {
        super(i18nProvider, token.getSigningCertificate(), token.getCertificateChain(), validationTime, context, position, validationPolicy);
    }

}
