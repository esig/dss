package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class BasicSignatureValidationProcess extends AbstractBasicValidationProcess<XmlValidationProcessBasicSignature> {

    /** List of timestamps within the signature */
    private final List<XmlTimestamp> xmlTimestamps;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param signatureWrapper {@link SignatureWrapper}
     * @param xmlTimestamps a collection of {@link XmlTimestamp} validations
     * @param bbbs           map of BasicBuildingBlocks
     */
    public BasicSignatureValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData, SignatureWrapper signatureWrapper,
                                           List<XmlTimestamp> xmlTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlValidationProcessBasicSignature(), diagnosticData, signatureWrapper, bbbs);
        this.xmlTimestamps = xmlTimestamps;
        result.setProofOfExistence(getCurrentTime(diagnosticData));
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPBS;
    }

    private XmlProofOfExistence getCurrentTime(DiagnosticData diagnosticData) {
        XmlProofOfExistence proofOfExistence = new XmlProofOfExistence();
        proofOfExistence.setTime(diagnosticData.getValidationDate());
        return proofOfExistence;
    }

    @Override
    protected List<TimestampWrapper> getContentTimestamps() {
        SignatureWrapper signature = diagnosticData.getSignatureById(token.getId());
        if (signature != null) {
            return signature.getContentTimestamps();
        }
        return Collections.emptyList();
    }

    @Override
    protected XmlValidationProcessTimestamp getTimestampValidation(String timestampId) {
        for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
            if (Utils.areStringsEqual(timestampId, xmlTimestamp.getId())) {
                return xmlTimestamp.getValidationProcessTimestamp();
            }
        }
        return null;
    }

}
