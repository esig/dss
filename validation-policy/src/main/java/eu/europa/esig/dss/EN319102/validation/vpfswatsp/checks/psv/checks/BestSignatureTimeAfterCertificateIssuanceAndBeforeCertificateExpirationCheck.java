package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.psv.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck extends ChainItem<XmlPSV> {

	private final Date bestSignatureTime;
	private final Date notBefore;
	private final Date notAfter;

	public BestSignatureTimeAfterCertificateIssuanceAndBeforeCertificateExpirationCheck(XmlPSV result, Date bestSignatureTime, Date notBefore, Date notAfter,
			LevelConstraint constraint) {
		super(result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
	}

	@Override
	protected boolean process() {
		return bestSignatureTime.after(notBefore) && bestSignatureTime.before(notAfter);
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
		return SubIndication.OUT_OF_BOUNDS_NO_POE;
	}

}
