package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class checks whether a document contains form fill or signing modifications occurred after the signature revision
 *
 */
public class FormFillChangesCheck extends ChainItem<XmlFC> {

    /** The PDF revision */
    private final PDFRevisionWrapper pdfRevision;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param pdfRevision {@link PDFRevisionWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public FormFillChangesCheck(I18nProvider i18nProvider, XmlFC result, PDFRevisionWrapper pdfRevision, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.pdfRevision = pdfRevision;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionEmpty(pdfRevision.getPdfSignatureOrFormFillChanges());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_DSCNFFSM;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_DSCNFFSM_ANS;
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
