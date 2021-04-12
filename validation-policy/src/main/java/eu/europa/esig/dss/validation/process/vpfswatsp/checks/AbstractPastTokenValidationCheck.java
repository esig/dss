package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Abstract class containing the main logic for PastSignatureValidation result check
 */
public abstract class AbstractPastTokenValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

    /** Past signature validation */
    private final XmlPSV xmlPSV;

    /** Indication */
    private Indication indication;

    /** SubIndication */
    private SubIndication subIndication;

    /** Past signature validation suffix */
    private static final String PSV_BLOCK_SUFFIX = "-PSV";

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessArchivalData}
     * @param token {@link TokenProxy}
     * @param xmlPSV {@link XmlPSV}
     * @param constraint {@link LevelConstraint}
     */
    public AbstractPastTokenValidationCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result,
                                        TokenProxy token, XmlPSV xmlPSV, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId() + PSV_BLOCK_SUFFIX);
        this.xmlPSV = xmlPSV;
    }

    @Override
    protected boolean process() {
        if (!isValid(xmlPSV)) {
            indication = xmlPSV.getConclusion().getIndication();
            subIndication = xmlPSV.getConclusion().getSubIndication();
            return false;
        }
        return true;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return indication;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return subIndication;
    }

}
