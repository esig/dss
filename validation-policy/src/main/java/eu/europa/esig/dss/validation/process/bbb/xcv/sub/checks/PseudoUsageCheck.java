package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import java.text.MessageFormat;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo.JoinedPseudoStrategy;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo.PseudoStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PseudoUsageCheck extends ChainItem<XmlSubXCV> {

	private final CertificateWrapper certificate;

	private String pseudo;

	public PseudoUsageCheck(XmlSubXCV result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		PseudoStrategy pseudoStrategy = new JoinedPseudoStrategy();
		pseudo = pseudoStrategy.getPseudo(certificate);
		return Utils.isStringEmpty(pseudo);
	}

	@Override
	protected String getAdditionalInfo() {
		if (Utils.isStringNotEmpty(pseudo)) {
			Object[] params = new Object[] { pseudo };
			return MessageFormat.format(AdditionalInfo.PSEUDO, params);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_PSEUDO_USE;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_PSEUDO_USE_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
