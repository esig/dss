package eu.europa.esig.dss.validation.process.qmatrix.tl.checks;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.qmatrix.EIDASUtils;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class TLVersionCheck extends ChainItem<XmlTLAnalysis> {

	private static final Logger LOG = LoggerFactory.getLogger(TLVersionCheck.class);

	private final XmlTrustedList currentTL;
	private final Date currentTime;
	private final ValueConstraint constraint;

	public TLVersionCheck(XmlTLAnalysis result, XmlTrustedList currentTl, Date currentTime, ValueConstraint constraint) {
		super(result, constraint);
		this.currentTL = currentTl;
		this.currentTime = currentTime;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {

		if (!EIDASUtils.isPostGracePeriod(currentTime)) {
			return true;
		}

		String expectedVersionString = constraint.getValue();
		int version = 5; // default eIDAS
		try {
			version = Integer.parseInt(expectedVersionString);
		} catch (NumberFormatException e) {
			LOG.warn("Unable to parse TLVersion constraint : '{0}'", expectedVersionString);
		}

		Integer tlVersion = currentTL.getVersion();
		if (tlVersion != null && tlVersion.intValue() == version) {
			return true;
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_TL_VERSION;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_TL_VERSION_ANS;
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
