package eu.europa.esig.dss.EN319102.bbb.isc.checks;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
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
		return StringUtils.equals(signingCertificateId, certificate.getId());
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
