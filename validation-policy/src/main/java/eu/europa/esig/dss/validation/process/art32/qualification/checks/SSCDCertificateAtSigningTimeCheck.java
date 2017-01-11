package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDFromCertAndTL;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SSCDCertificateAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final QualifiedStatus qualifiedStatus;
	private final List<TrustedServiceWrapper> servicesForESign;

	public SSCDCertificateAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign, QualifiedStatus qualifiedStatus, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.signingTime = signingTime;
		this.qualifiedStatus = qualifiedStatus;
		this.servicesForESign = new ArrayList<TrustedServiceWrapper>(servicesForESign);
	}

	@Override
	protected boolean process() {

		SSCDStrategy strategy = new SSCDFromCertAndTL(signingCertificate, servicesForESign, qualifiedStatus, signingTime);
		SSCDStatus status = strategy.getSSCDStatus();

		return SSCDStatus.SSCD == status;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_SSCD_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_SSCD_AT_ST_ANS;
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
