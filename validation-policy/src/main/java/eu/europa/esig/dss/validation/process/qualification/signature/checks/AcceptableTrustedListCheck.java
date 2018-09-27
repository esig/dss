package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import java.text.MessageFormat;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AcceptableTrustedListCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final XmlTLAnalysis tlAnalysis;

	public AcceptableTrustedListCheck(T result, XmlTLAnalysis tlAnalysis, LevelConstraint constraint) {
		super(result, constraint, tlAnalysis.getCountryCode());

		this.tlAnalysis = tlAnalysis;
	}

	@Override
	public boolean process() {
		return isValidConclusion(tlAnalysis.getConclusion());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TRUSTED_LIST_ACCEPT_ANS;
	}

	@Override
	protected String getAdditionalInfo() {
		Object[] params = new Object[] { tlAnalysis.getCountryCode() };
		return MessageFormat.format(AdditionalInfo.TRUSTED_LIST, params);
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
