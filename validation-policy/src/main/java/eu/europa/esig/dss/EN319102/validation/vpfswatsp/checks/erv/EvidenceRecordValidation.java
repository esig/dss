package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.TimestampComparator;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.checks.ArchiveTimestampsCoverEachOtherCheck;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.checks.ArchiveTimestampsValidationCheck;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.checks.FirstArchiveTimestampHashValueCorrectCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * 5.6.2.5 Evidence record validation building block
 */
public class EvidenceRecordValidation extends Chain<XmlERV> {

	private final SignatureWrapper signature;
	private final List<TimestampWrapper> archiveTimestamps;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	private final DiagnosticData diagnosticData;
	private final POEExtraction poe;
	private final ValidationPolicy policy;
	private final Date currentTime;

	protected EvidenceRecordValidation(SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs, DiagnosticData diagnosticData, POEExtraction poe,
			ValidationPolicy policy, Date currentTime) {
		super(new XmlERV());

		this.signature = signature;
		this.archiveTimestamps = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
		this.bbbs = bbbs;

		this.diagnosticData = diagnosticData;
		this.poe = poe;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected void initChain() {
		if (CollectionUtils.isEmpty(archiveTimestamps)) {
			return;
		}

		Collections.sort(archiveTimestamps, new TimestampComparator());

		/*
		 * 1) Verify that the first Archive Time-stamp of the first Archive Time-stamp Chain (the initial Archive
		 * Timestamp) of the Evidence Record contains the hash value of the data object or data object group according
		 * to the EncapsulatedContentInfo of the Signed Data object (group). If this is the case, the building block
		 * shall go to the next step. Otherwise, the building block shall return the indication FAILED.
		 */
		ChainItem<XmlERV> item = firstItem = firstArchiveTimestampHashValueCorrect(archiveTimestamps.get(0));

		/*
		 * 2) The building block shall verify each Archive Time-stamp Chain:
		 * a) The building block shall check that the first hash value list of each Archive Time-stamp (except the
		 * initial Archive Time-stamp) contains the hash value of the Time-stamp of the previous Archive Timestamp.
		 * If this is the case, the building block shall go to the next step. Otherwise, the building block shall
		 * return the indication FAILED.
		 */
		if (CollectionUtils.size(item) > 1) {
			item.setNextItem(archiveTimestampsCoverEachOther());
		}

		/*
		 * b) Performing the time stamp validation process (see clause 5.4) and if necessary, the past signature
		 * validation process (see clause 5.6.2.4):
		 * b1) The building block shall check that each Archive Time-stamp is valid relative to the time of the
		 * following Archive Time-stamp. If this is the case, the building block shall go to the next step.
		 * Otherwise, the building block shall return the indication FAILED.
		 */
		item.setNextItem(archiveTimestampsValidation());

		/*
		 * b2) The building block shall check that all Archive Time-stamps within a chain use the same hash
		 * algorithm and this algorithm is considered secure at the time of the first Archive Time-stamp of the
		 * following Archive Time-stamp Chain. If this is the case, the building block shall go to the next
		 * step. Otherwise, the building block shall return the indication FAILED.
		 */

	}

	private ChainItem<XmlERV> firstArchiveTimestampHashValueCorrect(TimestampWrapper firstTimestamp) {
		return new FirstArchiveTimestampHashValueCorrectCheck(result, signature, firstTimestamp, getFailLevelConstraint());
	}

	private ChainItem<XmlERV> archiveTimestampsCoverEachOther() {
		return new ArchiveTimestampsCoverEachOtherCheck(result, archiveTimestamps, getFailLevelConstraint());
	}

	private ChainItem<XmlERV> archiveTimestampsValidation() {
		return new ArchiveTimestampsValidationCheck(result, archiveTimestamps, bbbs, diagnosticData, poe, policy, currentTime, getFailLevelConstraint());
	}

}
