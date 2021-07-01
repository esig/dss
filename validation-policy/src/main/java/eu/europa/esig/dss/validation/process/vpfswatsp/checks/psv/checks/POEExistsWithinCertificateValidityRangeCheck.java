package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

/**
 * This check verifies if the set of POEs contains a POE for the certificate after the issuance date and
 * before the expiration date of that certificate.
 *
 */
public class POEExistsWithinCertificateValidityRangeCheck extends ChainItem<XmlPSV> {

    /** Certificate to check POE */
    private final CertificateWrapper certificate;

    /** A collection of POEs */
    private final POEExtraction poe;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlPSV}
     * @param certificate {@link CertificateWrapper} to check
     * @param poe {@link POEExtraction}
     * @param constraint {@link LevelConstraint}
     */
    public POEExistsWithinCertificateValidityRangeCheck(I18nProvider i18nProvider, XmlPSV result,
                                                        CertificateWrapper certificate, POEExtraction poe,
                                                        LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
        this.poe = poe;
    }

    @Override
    protected boolean process() {
        return certificate != null && poe.isPOEExistInRange(certificate.getId(), certificate.getNotBefore(), certificate.getNotAfter());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_IPCRIAIDBEDC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_IPCRIAIDBEDC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (certificate != null) {
            return i18nProvider.getMessage(MessageTag.CERTIFICATE_ID, certificate.getId());
        }
        return null;
    }

}
