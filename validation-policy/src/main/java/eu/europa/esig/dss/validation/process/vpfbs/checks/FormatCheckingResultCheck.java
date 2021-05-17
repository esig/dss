package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the format checking process as per clause 5.2.2 succeeded
 *
 */
public class FormatCheckingResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Format Checking building block suffix */
    private static final String FC_BLOCK_SUFFIX = "-FC";

    /** Format Checking process result */
    private final XmlFC xmlFC;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlFC {@link XmlFC}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public FormatCheckingResultCheck(I18nProvider i18nProvider, T result,
                                     XmlFC xmlFC, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + FC_BLOCK_SUFFIX);
        this.xmlFC = xmlFC;
    }

    @Override
    protected boolean process() {
        return xmlFC != null && isValid(xmlFC);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_IFCRC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_IFCRC_ANS;
    }

}
