package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationFromCertAndTL;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCertificateAtCertificateIssuanceCheck extends ChainItem<XmlSignatureAnalysis> {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> servicesForESign;

	public QualifiedCertificateAtCertificateIssuanceCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> servicesForESign, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.servicesForESign = new ArrayList<TrustedServiceWrapper>(servicesForESign);
	}

	@Override
	protected boolean process() {

		QualificationFromCertAndTL qualification = new QualificationFromCertAndTL(signingCertificate, servicesForESign, signingCertificate.getNotBefore());
		QualifiedStatus qualifiedStatus = qualification.getQualifiedStatus();

		return QualifiedStatus.QC_FOR_ESIGN == qualifiedStatus || QualifiedStatus.QC_NOT_FOR_ESIGN == qualifiedStatus;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_QC_AT_CC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_QC_AT_CC_ANS;
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
