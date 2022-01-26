package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;

/**
 * Verifies a signature according to given permissions for the signature field in /SigFieldLock
 *
 */
public class SigFieldLockCheck extends AbstractPdfLockDictionaryCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public SigFieldLockCheck(I18nProvider i18nProvider, XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
        super(i18nProvider, result, signature, signature.getSigFieldLock(), constraint);
    }

    @Override
    protected boolean process() {
        if (!super.process()) {
            return false;
        }
        if (!signature.arePdfObjectModificationsDetected()) {
            return true;
        }
        if (pdfLockDictionary == null) {
            return true;
        }

        // optional
        if (pdfLockDictionary.getPermissions() != null) {
            switch (pdfLockDictionary.getPermissions()) {
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
                            String.format("The value '%s' is not supported!", pdfLockDictionary.getPermissions()));
            }
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_ISVASFLD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_ISVASFLD_ANS;
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
