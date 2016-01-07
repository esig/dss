package eu.europa.esig.dss.EN319102.validation.vpfltvd.checks;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateValidityAtBestSignatureTimeCheck extends ChainItem<XmlValidationProcessLongTermData> {

	public SigningCertificateValidityAtBestSignatureTimeCheck(XmlValidationProcessLongTermData result, CertificateWrapper signingCertificate, Date bestSignatureTime,
			LevelConstraint constraint) {
		super(result, constraint);
	}

	@Override
	protected boolean process() {
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_ISCNVABST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_ISCNVABST_ANS;
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
