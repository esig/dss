package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks the certificate's QcType(s)
 */
public class CertificateQcTypeCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link MultiValuesConstraint}
     */
    public CertificateQcTypeCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                         MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        List<String> qcTypes = new ArrayList<>();
        for (QCType qcType : certificate.getQCTypes()) {
            // allow descriptions and oids
            qcTypes.add(qcType.getDescription());
            qcTypes.add(qcType.getOid());
        }
        return processValuesCheck(qcTypes);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCTA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCTA_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
    }

}
