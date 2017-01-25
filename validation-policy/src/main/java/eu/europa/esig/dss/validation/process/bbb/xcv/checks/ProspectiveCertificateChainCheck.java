package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ProspectiveCertificateChainCheck extends ChainItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final DiagnosticData diagnosticData;

	private final Context context;

	public ProspectiveCertificateChainCheck(XmlXCV result, CertificateWrapper certificate, DiagnosticData diagnosticData, Context context,
			LevelConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
		this.diagnosticData = diagnosticData;
		this.context = context;
	}

	@Override
	protected boolean process() {
		if (certificate.isTrusted()) {
			return true;
		}
		String lastChainCertId = certificate.getLastChainCertificateId();
		final CertificateWrapper lastChainCertificate = diagnosticData.getUsedCertificateByIdNullSafe(lastChainCertId);
		return lastChainCertificate.isTrusted();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CCCBB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
			return MessageTag.BBB_XCV_CCCBB_SIG_ANS;
		case COUNTER_SIGNATURE:
			return MessageTag.BBB_XCV_CCCBB_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.BBB_XCV_CCCBB_TSP_ANS;
		case REVOCATION:
			return MessageTag.BBB_XCV_CCCBB_REV_ANS;
		default:
			return MessageTag.BBB_XCV_CCCBB_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
