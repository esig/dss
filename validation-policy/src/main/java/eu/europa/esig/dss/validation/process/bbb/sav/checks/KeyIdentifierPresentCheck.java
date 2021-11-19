package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies whether a 'kid' (key identifier) header parameter is present within
 * the protected header of a signature
 *
 */
public class KeyIdentifierPresentCheck extends ChainItem<XmlSAV> {

    /** The signature to verify */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public KeyIdentifierPresentCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
                                     LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        return signature.getKeyIdentifierReference() != null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_ICS_ISAKIDP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_ICS_ISAKIDP_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
    }

}
