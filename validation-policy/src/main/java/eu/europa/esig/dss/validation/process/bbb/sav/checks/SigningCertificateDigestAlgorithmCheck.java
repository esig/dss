package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestCryptographicChecker;

import java.util.Date;

/**
 * Verifies a DigestAlgorithm used for a signing-certificate-reference
 *
 */
public class SigningCertificateDigestAlgorithmCheck<T extends XmlConstraintsConclusion> extends
        SigningCertificateRefDigestCryptographicCheckerResultCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider          {@link I18nProvider}
     * @param result                the result
     * @param validationDate        {@link Date}
     * @param certificateRefWrapper {@link CertificateRefWrapper}
     * @param cryptographicConstraint {@link CryptographicConstraint}
     * @param constraint            {@link LevelConstraint}
     */
    public SigningCertificateDigestAlgorithmCheck(I18nProvider i18nProvider, CertificateRefWrapper certificateRefWrapper,
                                                  T result, Date validationDate, CryptographicConstraint cryptographicConstraint,
                                                  LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, certificateRefWrapper,
                execute(i18nProvider, certificateRefWrapper.getDigestMethod(), validationDate, cryptographicConstraint), constraint);
    }

    private static XmlCC execute(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, Date validationDate,
                                 CryptographicConstraint constraint) {
        DigestCryptographicChecker dac = new DigestCryptographicChecker(i18nProvider, digestAlgorithm, validationDate,
                MessageTag.ACCM_POS_SIG_CERT_REF, constraint);
        return dac.execute();
    }

}
