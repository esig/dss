package eu.europa.esig.dss.EN319102.validation.vpfswatsp;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.EvidenceRecordValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	private final SignatureWrapper signature;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final DiagnosticData diagnosticData;
	private final ValidationPolicy policy;
	private final Date currentTime;

	public ValidationProcessForSignaturesWithArchivalData(SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs, DiagnosticData diagnosticData,
			ValidationPolicy policy, Date currentTime) {
		super(new XmlValidationProcessArchivalData());

		this.signature = signature;
		this.bbbs = bbbs;
		this.diagnosticData = diagnosticData;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected void initChain() {
		ChainItem<XmlValidationProcessArchivalData> item = null;

		List<TimestampWrapper> archiveTimestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);

		if (CollectionUtils.isNotEmpty(archiveTimestamps)) {

			/*
			 * 5.6.3.4
			 * 1) If there is one or more evidence records, the long term validation process shall perform the
			 * evidence record validation process for each of them according to clause 5.6.2.5. If the evidence record
			 * validation process returns PASSED, the SVA shall go to step 6.
			 */
			firstItem = item = evidenceRecordValidationProcess(archiveTimestamps);

			/*
			 * 2) POE initialization: the long term validation process shall add a POE for each object in the signature
			 * at the current time to the set of POEs.
			 * NOTE 1: The set of POE in the input may have been initialized from external sources (e.g. provided from
			 * an external archiving system). These POEs will be used without additional processing.
			 */
			POEExtraction poe = initPOE(archiveTimestamps);

		}

	}

	private POEExtraction initPOE(List<TimestampWrapper> archiveTimestamps) {
		POEExtraction poe = new POEExtraction();

		for (TimestampWrapper timestamp : archiveTimestamps) {
			poe.extractPOE(timestamp, diagnosticData);
		}

		return poe;
	}

	private ChainItem<XmlValidationProcessArchivalData> evidenceRecordValidationProcess(List<TimestampWrapper> archiveTsps) {
		return new EvidenceRecordValidationCheck(result, signature, archiveTsps, getFailLevelConstraint());
	}

}
