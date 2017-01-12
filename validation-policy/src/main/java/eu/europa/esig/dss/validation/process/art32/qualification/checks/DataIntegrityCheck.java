package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class DataIntegrityCheck extends ChainItem<XmlSignatureAnalysis> {

	private final SignatureWrapper signature;

	public DataIntegrityCheck(XmlSignatureAnalysis result, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
	}

	@Override
	protected boolean process() {
		return signature.isReferenceDataFound() && signature.isReferenceDataIntact();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_DATA_INTEGRITY;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_DATA_INTEGRITY_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
