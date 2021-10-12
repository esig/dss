package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;

/**
 * Verifies the validation result of a {@code PastSignatureValidationCertificateRevocationSelector}
 *
 */
public class PastSignatureValidationCertificateRevocationSelectorResultCheck extends CertificateRevocationSelectorResultCheck<XmlPSV> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       the result
     * @param crsResult    {@link XmlCRS}
     * @param constraint   {@link LevelConstraint}
     */
    public PastSignatureValidationCertificateRevocationSelectorResultCheck(
            I18nProvider i18nProvider, XmlPSV result, XmlCRS crsResult, LevelConstraint constraint) {
        super(i18nProvider, result, crsResult, constraint);
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.PSV_CRS;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (Utils.isCollectionNotEmpty(crsResult.getAcceptableRevocationId())) {
            return i18nProvider.getMessage(MessageTag.ACCEPTABLE_REVOCATION, crsResult.getAcceptableRevocationId());
        }
        return null;
    }

}
