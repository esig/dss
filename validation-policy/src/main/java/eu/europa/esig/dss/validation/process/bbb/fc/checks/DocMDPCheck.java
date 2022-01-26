package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies a signature according to given permissions for the document in /DocMDP
 *
 */
public class DocMDPCheck extends ChainItem<XmlFC> {

    /** The PDF signature to be checked */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public DocMDPCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        if (!signature.arePdfObjectModificationsDetected()) {
            return true;
        }
        CertificationPermission docMDPPermissions = signature.getDocMDPPermissions();
        if (docMDPPermissions == null) {
            return true;
        }
        switch (docMDPPermissions) {
            case NO_CHANGE_PERMITTED:
                if (Utils.isCollectionNotEmpty(signature.getPdfSignatureOrFormFillChanges()) ||
                        Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()) ||
                        Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges())) {
                    return false;
                }
                break;
            case MINIMAL_CHANGES_PERMITTED:
                if (Utils.isCollectionNotEmpty(signature.getPdfAnnotationChanges()) ||
                        Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges())) {
                    return false;
                }
                break;
            case CHANGES_PERMITTED:
                if (Utils.isCollectionNotEmpty(signature.getPdfUndefinedChanges())) {
                    return false;
                }
                break;
            default:
                throw new UnsupportedOperationException(
                        String.format("The value '%s' is not supported!", docMDPPermissions));
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISVADMDPD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISVADMDPD_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
