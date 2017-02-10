package eu.europa.esig.dss.validation.process.bbb.isc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SigningCertificateRecognitionCheck extends ChainItem<XmlISC> {

	private final TokenProxy token;
	private final DiagnosticData diagnosticData;

	public SigningCertificateRecognitionCheck(XmlISC result, TokenProxy token, DiagnosticData diagnosticData, LevelConstraint constraint) {
		super(result, constraint);
		this.token = token;
		this.diagnosticData = diagnosticData;
	}

	@Override
	protected boolean process() {
		String signingCertificateId = token.getSigningCertificateId();
		CertificateWrapper certificate = diagnosticData.getUsedCertificateByIdNullSafe(signingCertificateId);
		if (Utils.areStringsEqual(signingCertificateId, certificate.getId())) {
			return true;
		} else {
			return false;
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_ISCI;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_ISCI_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
	}

}
