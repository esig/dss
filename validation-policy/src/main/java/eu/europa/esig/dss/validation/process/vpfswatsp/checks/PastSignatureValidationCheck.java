package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.PastSignatureValidation;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PastSignatureValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

	private final SignatureWrapper signature;
	private final DiagnosticData diagnosticData;
	private final XmlBasicBuildingBlocks bbb;
	private final POEExtraction poe;
	private final Date currentTime;
	private final ValidationPolicy policy;
	private final Context context;

	private Indication indication;
	private SubIndication subIndication;

	public PastSignatureValidationCheck(XmlValidationProcessArchivalData result, SignatureWrapper signature, DiagnosticData diagnosticData,
			XmlBasicBuildingBlocks bbb, POEExtraction poe, Date currentTime, ValidationPolicy policy, Context context, LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
		this.diagnosticData = diagnosticData;
		this.bbb = bbb;
		this.poe = poe;
		this.currentTime = currentTime;
		this.policy = policy;
		this.context = context;
	}

	@Override
	protected boolean process() {
		PastSignatureValidation psv = new PastSignatureValidation(signature, diagnosticData, bbb, poe, currentTime, policy, context);
		XmlPSV psvResult = psv.execute();
		bbb.setPSV(psvResult);

		if (isValid(psvResult)) {
			return true;
		} else {
			indication = psvResult.getConclusion().getIndication();
			subIndication = psvResult.getConclusion().getSubIndication();
			return false;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPSVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPSVC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
