package eu.europa.esig.dss.validation.process.vpfswatsp.checks.erv.checks;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjectsType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampedTimestamp;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.TimestampWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ArchiveTimestampsCoverEachOtherCheck extends ChainItem<XmlERV> {

	private final List<TimestampWrapper> archiveTimestamps;

	public ArchiveTimestampsCoverEachOtherCheck(XmlERV result, List<TimestampWrapper> archiveTimestamps, LevelConstraint constraint) {
		super(result, constraint);

		this.archiveTimestamps = archiveTimestamps;
	}

	@Override
	protected boolean process() {
		TimestampWrapper previous = null;
		for (TimestampWrapper timestampWrapper : archiveTimestamps) {
			if (previous != null) {
				XmlSignedObjectsType signedObjects = timestampWrapper.getSignedObjects();
				boolean found = false;
				if (signedObjects != null && CollectionUtils.isNotEmpty(signedObjects.getSignedSignature())) {
					List<XmlTimestampedTimestamp> signedTimestamps = signedObjects.getTimestampedTimestamp();
					for (XmlTimestampedTimestamp xmlTsp : signedTimestamps) {
						if (StringUtils.equals(xmlTsp.getId(), previous.getId())) {
							found = true;
							break;
						}
					}
				}
				if (!found) {
					return false;
				}
			}
			previous = timestampWrapper;
		}

		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ERV_ATSCEO;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ERV_ATSCEO_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
