package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

/**
 * This class is used to check whether a determined PDF/A profile of the input document is acceptable.
 *
 */
public class PDFAProfileCheck extends AbstractMultiValuesCheckItem<XmlFC> {

    /** PDF/A Profile name */
    private final String pdfaProfile;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param pdfaProfile {@link String}
     * @param constraint {@link MultiValuesConstraint}
     */
    public PDFAProfileCheck(I18nProvider i18nProvider, XmlFC result, String pdfaProfile,
                              MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.pdfaProfile = pdfaProfile;
    }

    @Override
    protected boolean process() {
        return processValueCheck(pdfaProfile);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_DDAPDFAF;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_DDAPDFAF_ANS;
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
