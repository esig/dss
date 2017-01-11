package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
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

public class QualifiedCertificateAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final List<TrustedServiceWrapper> servicesForESign;

	public QualifiedCertificateAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.signingTime = signingTime;
		this.servicesForESign = new ArrayList<TrustedServiceWrapper>(servicesForESign);
	}

	@Override
	protected boolean process() {

		QualificationFromCertAndTL qualification = new QualificationFromCertAndTL(signingCertificate, servicesForESign, signingTime);
		QualifiedStatus qualifiedStatus = qualification.getQualifiedStatus();

		return QualifiedStatus.QC_FOR_ESIGN == qualifiedStatus || QualifiedStatus.QC_NOT_FOR_ESIGN == qualifiedStatus;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ART32_QC_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ART32_QC_AT_ST_ANS;
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
