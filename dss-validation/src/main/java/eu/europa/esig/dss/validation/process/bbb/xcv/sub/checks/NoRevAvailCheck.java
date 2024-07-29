package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This check verifies certificate's compliance to the RFC 9608,
 *
 */
public class NoRevAvailCheck extends ChainItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSubXCV} the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public NoRevAvailCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                        LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        /*
         * RFC 9608 "3. Other X.509 Certificate Extensions".
         *
         * If the noRevAvail extension is present in a certificate, then:
         *
         * - The certificate MUST NOT also include the basic constraints
         *   certificate extension with the cA BOOLEAN set to TRUE; see
         *   Section 4.2.1.9 of [RFC5280].
         *
         * - The certificate MUST NOT also include the CRL Distribution Points
         *   certificate extension; see Section 4.2.1.13 of [RFC5280].
         *
         * - The certificate MUST NOT also include the Freshest CRL certificate
         *   extension; see Section 4.2.1.15 of [RFC5280].
         *
         * - The Authority Information Access certificate extension, if
         *   present, MUST NOT include an id-ad-ocsp accessMethod; see
         *   Section 4.2.2.1 of [RFC5280].
         */
        if (certificate.isNoRevAvail()) {
            return !certificate.isCA() && Utils.isCollectionEmpty(certificate.getCRLDistributionPoints())
                    && Utils.isCollectionEmpty(certificate.getFreshestCRLUrls())
                    && Utils.isCollectionEmpty(certificate.getOCSPAccessUrls());
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_ICNRAEV;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_ICNRAEV_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE;
    }

}
