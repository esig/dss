package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies whether a used {@code eu.europa.esig.dss.enumerations.DigestAlgorithm}
 * for a signing-certificate-reference signing-attribute is reliable and acceptable at validation time
 *
 */
public class SigningCertificateRefDigestCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion>
        extends DigestCryptographicCheckerResultCheck<T> {

    /** The certificate reference being validated */
    private final CertificateRefWrapper certificateRefWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param validationDate {@link Date}
     * @param certificateRefWrapper {@link CertificateRefWrapper}
     * @param ccResult {@link XmlCC}
     * @param constraint {@link LevelConstraint}
     */
    public SigningCertificateRefDigestCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result,
                    Date validationDate, CertificateRefWrapper certificateRefWrapper,
                    XmlCC ccResult, LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, MessageTag.ACCM_POS_SIG_CERT_REF, ccResult, constraint);
        this.certificateRefWrapper = certificateRefWrapper;
    }

    @Override
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
        if (isValid(ccResult)) {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_ID,
                    ccResult.getVerifiedAlgorithm().getName(), dateTime, position, certificateRefWrapper.getCertificateId());
        } else {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID,
                    getErrorMessage(), dateTime, position, certificateRefWrapper.getCertificateId());
        }
    }

}
