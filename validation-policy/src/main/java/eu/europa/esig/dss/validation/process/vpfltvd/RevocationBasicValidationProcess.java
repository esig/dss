package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationBasicValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.vpfbs.AbstractBasicValidationProcess;

import java.util.Map;

/**
 * Performs basic validation of a revocation data
 */
public class RevocationBasicValidationProcess extends AbstractBasicValidationProcess<XmlRevocationBasicValidation> {

    /**
     * Revocation data to be validated
     */
    private final RevocationWrapper revocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param revocationData {@link RevocationWrapper}
     * @param bbbs           map of BasicBuildingBlocks
     */
    public RevocationBasicValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                            RevocationWrapper revocationData, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlRevocationBasicValidation(), diagnosticData, revocationData, bbbs);
        this.revocationData = revocationData;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFRVC;
    }

    @Override
    protected void addAdditionalInfo() {
        result.setId(revocationData.getId());
    }

}
