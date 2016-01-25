package eu.europa.esig.dss.validation.process.vpfswatsp.checks.erv;

import java.util.Date;
import java.util.Map;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlERV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class EvidenceRecordValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final SignatureWrapper signature;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;
	private final DiagnosticData diagnosticData;
	private final POEExtraction poe;
	private final ValidationPolicy policy;
	private final Date currentTime;

	public EvidenceRecordValidationCheck(XmlValidationProcessArchivalData result, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs,
			DiagnosticData diagnosticData, POEExtraction poe, ValidationPolicy policy, Date currentTime, LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
		this.bbbs = bbbs;
		this.diagnosticData = diagnosticData;
		this.poe = poe;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	@Override
	protected boolean process() {
		EvidenceRecordValidation erv = new EvidenceRecordValidation(signature, bbbs, diagnosticData, poe, policy, currentTime);
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
