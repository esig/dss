package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeFromCertAndTL;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ForeSignatureAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> implements TypeStrategy {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final List<TrustedServiceWrapper> caqcServices;

	private Type type;

	public ForeSignatureAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> caqcServices, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.signingTime = signingTime;
		this.caqcServices = new ArrayList<TrustedServiceWrapper>(caqcServices);
	}

	@Override
	protected boolean process() {
		TypeFromCertAndTL typeStrategy = new TypeFromCertAndTL(signingCertificate, caqcServices, signingTime);
		type = typeStrategy.getType();
		return Type.ESIGN == type;
	}

	@Override
	public Type getType() {
		return type;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_FOR_SIGN_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_FOR_SIGN_AT_ST_ANS;
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
