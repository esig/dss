package eu.europa.esig.dss.validation.process.art32.qualification.checks;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSignatureAnalysis;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDFromCertAndTL;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SSCDCertificateAtSigningTimeCheck extends ChainItem<XmlSignatureAnalysis> implements Condition {

	private final CertificateWrapper signingCertificate;
	private final Date signingTime;
	private final Condition qualified;
	private final List<TrustedServiceWrapper> servicesForESign;

	private SSCDStatus status;

	public SSCDCertificateAtSigningTimeCheck(XmlSignatureAnalysis result, CertificateWrapper signingCertificate, Date signingTime,
			List<TrustedServiceWrapper> servicesForESign, Condition qualified, LevelConstraint constraint) {
		super(result, constraint);

		this.signingCertificate = signingCertificate;
		this.signingTime = signingTime;
		this.qualified = qualified;
		this.servicesForESign = new ArrayList<TrustedServiceWrapper>(servicesForESign);
	}

	@Override
	public boolean check() {
		return SSCDStatus.SSCD == status;
	}

	@Override
	protected boolean process() {

		SSCDStrategy strategy = new SSCDFromCertAndTL(signingCertificate, servicesForESign, qualified, signingTime);
		status = strategy.getSSCDStatus();

		return check();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_SSCD_AT_ST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_SSCD_AT_ST_ANS;
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
