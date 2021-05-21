package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the identification of the signing certificate (as per clause 5.2.3) succeeded
 *
 */
public class IdentificationOfSigningCertificateResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Identification of Signing Certificate building block suffix */
    private static final String ISC_BLOCK_SUFFIX = "-ISC";

    /** Identification of the Signing Certificate building block result */
    private final XmlISC xmlISC;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlISC {@link XmlISC}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public IdentificationOfSigningCertificateResultCheck(I18nProvider i18nProvider, T result,
                                                         XmlISC xmlISC, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + ISC_BLOCK_SUFFIX);
        this.xmlISC = xmlISC;
    }

    @Override
    protected boolean process() {
        return xmlISC != null && isValid(xmlISC);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_IISCRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IISCRC_ANS;
    }

}
