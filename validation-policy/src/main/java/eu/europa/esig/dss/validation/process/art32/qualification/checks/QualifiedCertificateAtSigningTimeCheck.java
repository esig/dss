package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationFromCertAndTL;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCertificateAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> implements QualificationStrategy, Condition {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final List<TrustedServiceWrapper> servicesForESign;

	private QualifiedStatus status;

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
		status = qualification.getQualifiedStatus();

		return check();
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		return status;
	}

	@Override
	public boolean check() {
		return QualifiedStatus.isQC(status);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QC_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QC_AT_ST_ANS;
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
