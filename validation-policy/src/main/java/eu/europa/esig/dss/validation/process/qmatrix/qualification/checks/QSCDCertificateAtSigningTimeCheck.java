package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDFromCertAndTL;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStatus;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class QSCDCertificateAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> implements Condition {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final Condition qualified;
	private final List<TrustedServiceWrapper> caqcServices;

	private QSCDStatus status;

	public QSCDCertificateAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> caqcServices, Condition qualified, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.signingTime = signingTime;
		this.qualified = qualified;
		this.caqcServices = new ArrayList<TrustedServiceWrapper>(caqcServices);
	}

	@Override
	public boolean check() {
		return QSCDStatus.QSCD == status;
	}

	@Override
	protected boolean process() {

		QSCDStrategy strategy = new QSCDFromCertAndTL(signingCertificate, caqcServices, qualified, signingTime);
		status = strategy.getQSCDStatus();

		return check();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_QSCD_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_QSCD_AT_ST_ANS;
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
