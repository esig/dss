package eu.europa.esig.dss.validation.process.vpfswatsp.checks.erv.checks;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedObjectsType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignedSignature;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.SignatureWrapper;
import eu.europa.esig.dss.validation.wrappers.TimestampWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class FirstArchiveTimestampHashValueCorrectCheck extends ChainItem<XmlERV> {

	private final SignatureWrapper signature;
	private final TimestampWrapper archiveTimestamp;

	public FirstArchiveTimestampHashValueCorrectCheck(XmlERV result, SignatureWrapper signature, TimestampWrapper archiveTimestamp,
			LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
		this.archiveTimestamp = archiveTimestamp;
	}

	@Override
	protected boolean process() {
		String expectedSignatureId = signature.getId();

		XmlSignedObjectsType signedObjects = archiveTimestamp.getSignedObjects();
		if (signedObjects != null && CollectionUtils.isNotEmpty(signedObjects.getSignedSignature())) {
			List<XmlSignedSignature> signedSignatures = signedObjects.getSignedSignature();
			String firstSignatureId = signedSignatures.get(0).getId();
			return StringUtils.equals(expectedSignatureId, firstSignatureId);
		}

		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ERV_FATSPCS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ERV_FATSPCS_ANS;
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
