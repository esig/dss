package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.ArchiveTimestampsCoverEachOtherCheck;
import eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv.FirstArchiveTimestampHashValueCorrectCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.6.2.5 Evidence record validation building block
 */
public class EvidenceRecordValidation extends Chain<XmlERV> {

	private final SignatureWrapper signature;
	private final List<TimestampWrapper> archiveTimestamps;

	protected EvidenceRecordValidation(SignatureWrapper signature, List<TimestampWrapper> archiveTimestamps) {
		super(new XmlERV());

		this.signature = signature;
		this.archiveTimestamps = archiveTimestamps;
	}

	@Override
	protected void initChain() {

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

	}

	private ChainItem<XmlERV> firstArchiveTimestampHashValueCorrect(TimestampWrapper firstTimestamp) {
		return new FirstArchiveTimestampHashValueCorrectCheck(result, signature, firstTimestamp, getFailLevelConstraint());
	}

	private ChainItem<XmlERV> archiveTimestampsCoverEachOther() {
		return new ArchiveTimestampsCoverEachOtherCheck(result, archiveTimestamps, getFailLevelConstraint());
	}

	// TODO uses validation policy
	private LevelConstraint getFailLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		return constraint;
	}

}
