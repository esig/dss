package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.psv.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class BestSignatureTimeNotBeforeCertificateIssuanceCheck extends ChainItem<XmlPSV> {

	private final Date bestSignatureTime;
	private final Date notBefore;

	public BestSignatureTimeNotBeforeCertificateIssuanceCheck(XmlPSV result, Date bestSignatureTime, Date notBefore, LevelConstraint constraint) {
		super(result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.notBefore = notBefore;
	}

	@Override
	protected boolean process() {
		return !bestSignatureTime.before(notBefore);
	}

	@Override
	protected MessageTag getMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NOT_YET_VALID;
	}

}
