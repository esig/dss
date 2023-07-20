package eu.europa.esig.dss.validation.process.vpftsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.qualification.timestamp.TimestampQualificationBlock;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to perform validation for all available timestamps,
 * as well as to extract POE information for valid entries
 *
 */
public class AllTimestampValidationBlock {

    /** The i18n provider */
    private final I18nProvider i18nProvider;

    /** The DiagnosticData to use */
    private final DiagnosticData diagnosticData;

    /** The validation policy */
    protected final ValidationPolicy policy;

    /** The validation time */
    protected final Date currentTime;

    /** Map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** List of Trusted List validations */
    private final List<XmlTLAnalysis> tlAnalysis;

    /** The target highest validation level */
    private final ValidationLevel validationLevel;

    /** Contains list of all POEs */
    private final POEExtraction poe;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param policy {@link ValidationPolicy}
     * @param currentTime {@link Date} validation time
     * @param bbbs map of {@link XmlBasicBuildingBlocks} to fill the validation result
     * @param tlAnalysis a list of {@link XmlTLAnalysis}
     * @param validationLevel {@link ValidationLevel} the target highest level
     * @param poe {@link POEExtraction} to be filled with POE from valid timestamps
     */
    public AllTimestampValidationBlock(final I18nProvider i18nProvider, final DiagnosticData diagnosticData,
            final ValidationPolicy policy, final Date currentTime, final Map<String, XmlBasicBuildingBlocks> bbbs,
            final List<XmlTLAnalysis> tlAnalysis, final ValidationLevel validationLevel, final POEExtraction poe) {
        this.i18nProvider = i18nProvider;
        this.diagnosticData = diagnosticData;
        this.policy = policy;
        this.currentTime = currentTime;
        this.bbbs = bbbs;
        this.tlAnalysis = tlAnalysis;
        this.validationLevel = validationLevel;
        this.poe = poe;
    }

    /**
     * This method performs validation of timestamps, but also fills the {@code POEExtraction} object for valid timestamps
     *
     * @return a map of {@link XmlTimestamp} identifiers and their corresponding validations
     */
    public Map<String, XmlTimestamp> execute() {
        final Map<String, XmlTimestamp> result = new HashMap<>();

        List<TimestampWrapper> timestampList = new ArrayList<>(diagnosticData.getTimestampList());
        timestampList.sort(Comparator.comparing(TimestampWrapper::getProductionTime).reversed());

        for (TimestampWrapper newestTimestamp : timestampList) {
            XmlTimestamp xmlTimestamp = buildXmlTimestamp(newestTimestamp, bbbs, tlAnalysis);
            result.put(newestTimestamp.getId(), xmlTimestamp);

            XmlConclusion latestConclusion = xmlTimestamp.getValidationProcessTimestamp().getConclusion();
            if (latestConclusion != null && ValidationProcessUtils.isAllowedBasicTimestampValidation(latestConclusion)) {
                if (Indication.PASSED == latestConclusion.getIndication()) {
                    poe.extractPOE(newestTimestamp);

                } else if (ValidationLevel.ARCHIVAL_DATA.equals(validationLevel)) {
                    PastSignatureValidation psv = new PastSignatureValidation(i18nProvider, newestTimestamp, bbbs,
                            latestConclusion, poe, currentTime, policy, Context.TIMESTAMP);
                    XmlPSV psvResult = psv.execute();

                    XmlBasicBuildingBlocks tstBBB = bbbs.get(newestTimestamp.getId());
                    tstBBB.setPSV(psvResult);
                    enrichBBBWithPSVConclusion(tstBBB, psvResult);

                    latestConclusion = psvResult.getConclusion();
                    if (latestConclusion != null && Indication.PASSED == latestConclusion.getIndication()) {
                        poe.extractPOE(newestTimestamp);
                    }
                }
            }
        }

        return result;
    }

    private XmlTimestamp buildXmlTimestamp(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs,
                                           List<XmlTLAnalysis> tlAnalysis) {
        XmlTimestamp xmlTimestamp = new XmlTimestamp();
        xmlTimestamp.setId(timestamp.getId());

        TimestampBasicValidationProcess vpftsp = new TimestampBasicValidationProcess(i18nProvider, diagnosticData, timestamp, bbbs);
        xmlTimestamp.setValidationProcessTimestamp(vpftsp.execute());

        // Timestamp qualification
        if (policy.isEIDASConstraintPresent()) {
            TimestampQualificationBlock timestampQualificationBlock = new TimestampQualificationBlock(
                    i18nProvider, timestamp, tlAnalysis, poe);
            xmlTimestamp.setValidationTimestampQualification(timestampQualificationBlock.execute());
        }
        return xmlTimestamp;
    }

    private void enrichBBBWithPSVConclusion(XmlBasicBuildingBlocks bbb, XmlPSV psv) {
        XmlConclusion bbbConclusion = bbb.getConclusion();
        XmlConclusion psvConclusion = psv.getConclusion();
        bbbConclusion.setIndication(psvConclusion.getIndication());
        bbbConclusion.setSubIndication(psvConclusion.getSubIndication());
        bbbConclusion.getErrors().addAll(psvConclusion.getErrors());
        bbbConclusion.getWarnings().addAll(psvConclusion.getWarnings());
        bbbConclusion.getInfos().addAll(psvConclusion.getInfos());
    }

}
