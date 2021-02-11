package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.PSD2InfoWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RoleOfPspOid;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks the certificate's QcPS2D Role
 */
public class CertificatePS2DQcRolesOfPSPCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

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
    public CertificatePS2DQcRolesOfPSPCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                            MultiValuesConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        List<String> values = new ArrayList<>();
        PSD2InfoWrapper psd2Info = certificate.getPSD2Info();
        if (psd2Info != null) {
            values.addAll(psd2Info.getRoleOfPSPNames());
            for (RoleOfPspOid roleOfPspOid : psd2Info.getRoleOfPSPOids()) {
                values.add(roleOfPspOid.getDescription());
                values.add(roleOfPspOid.getOid());
            }
        }
        return processValuesCheck(values);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCRA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCICQCRA_ANS;
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
