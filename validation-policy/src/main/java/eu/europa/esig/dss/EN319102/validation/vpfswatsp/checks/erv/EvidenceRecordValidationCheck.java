package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.erv;

import java.util.List;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class EvidenceRecordValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final SignatureWrapper signature;
	private final List<TimestampWrapper> archiveTimestamps;

	public EvidenceRecordValidationCheck(XmlValidationProcessArchivalData result, SignatureWrapper signature, List<TimestampWrapper> archiveTsps,
			LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
		this.archiveTimestamps = archiveTsps;
	}

	@Override
	protected boolean process() {
		EvidenceRecordValidation erv = new EvidenceRecordValidation(signature, archiveTimestamps);
		XmlERV xmlERV = erv.execute();
		XmlConclusion ervConclusion = xmlERV.getConclusion();
		if (Indication.VALID.equals(ervConclusion.getIndication())) {
			return true;
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ERV_IERVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ERV_IERVC_ANS;
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
