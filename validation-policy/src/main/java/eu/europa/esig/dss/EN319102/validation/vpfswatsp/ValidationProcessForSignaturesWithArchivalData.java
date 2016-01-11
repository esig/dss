package eu.europa.esig.dss.EN319102.validation.vpfswatsp;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.EvidenceRecordValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.6 Validation process for Signatures with Archival Data
 */
public class ValidationProcessForSignaturesWithArchivalData extends Chain<XmlValidationProcessArchivalData> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;
	private final List<TimestampWrapper> archiveTimestamps;

	public ValidationProcessForSignaturesWithArchivalData(DiagnosticData diagnosticData, SignatureWrapper signature) {
		super(new XmlValidationProcessArchivalData());

		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.archiveTimestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	@Override
	protected void initChain() {

		ChainItem<XmlValidationProcessArchivalData> item = null;

		/*
		 * 5.6.3.4 1) If there is one or more evidence records, the long term validation process shall perform the
		 * evidence record validation process for each of them according to clause 5.6.2.5. If the evidence record
		 * validation process returns PASSED, the SVA shall go to step 6.
		 */
		if (CollectionUtils.isNotEmpty(archiveTimestamps)) {
			firstItem = item = evidenceRecordValidationProcess(archiveTimestamps);
		}

	}

	private ChainItem<XmlValidationProcessArchivalData> evidenceRecordValidationProcess(List<TimestampWrapper> archiveTsps) {
		return new EvidenceRecordValidationCheck(result, signature, archiveTimestamps, getFailLevelConstraint());
	}

	// TODO uses validation policy
	private LevelConstraint getFailLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		return constraint;
	}

}
