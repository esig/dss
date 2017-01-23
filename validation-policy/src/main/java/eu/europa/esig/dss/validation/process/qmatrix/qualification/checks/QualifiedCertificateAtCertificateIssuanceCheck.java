package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationFromCertAndTL;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QualifiedCertificateAtCertificateIssuanceCheck extends ChainItem<XmlSignatureAnalysis> implements QualificationStrategy {

	private final CertificateWrapper signingCertificate;
	private final List<TrustedServiceWrapper> caqcServices;

	private QualifiedStatus status;

	public QualifiedCertificateAtCertificateIssuanceCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate,
			List<TrustedServiceWrapper> caqcServices, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.caqcServices = new ArrayList<TrustedServiceWrapper>(caqcServices);
	}

	@Override
	protected boolean process() {
		QualificationFromCertAndTL qualification = new QualificationFromCertAndTL(signingCertificate, caqcServices, signingCertificate.getNotBefore());
		status = qualification.getQualifiedStatus();
		return qualification.check();
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		return status;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QC_AT_CC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QC_AT_CC_ANS;
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
