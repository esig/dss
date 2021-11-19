package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies whether a value of the signed attribute 'kid' (key identifier), when present, matches
 * the signing-certificate sued to create the signature
 */
public class KeyIdentifierMatchCheck extends ChainItem<XmlSAV> {

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
    public KeyIdentifierMatchCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
                                     LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        CertificateRefWrapper keyIdentifierReference = signature.getKeyIdentifierReference();
        if (keyIdentifierReference != null) {
            return keyIdentifierReference.isIssuerSerialMatch();
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_ICS_DKIDVM;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_ICS_DKIDVM_ANS;
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
