package eu.europa.esig.dss.validation.process.qmatrix.tl;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlTLAnalysis;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.qmatrix.tl.checks.TLFreshnessCheck;
import eu.europa.esig.dss.validation.process.qmatrix.tl.checks.TLNotExpiredCheck;
import eu.europa.esig.dss.validation.process.qmatrix.tl.checks.TLVersionCheck;
import eu.europa.esig.dss.validation.process.qmatrix.tl.checks.TLWellSignedCheck;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class TLValidationBlock extends Chain<XmlTLAnalysis> {

	private final XmlTrustedList currentTL;
	private final Date currentTime;
	private final ValidationPolicy policy;

	public TLValidationBlock(XmlTrustedList currentTL, Date currentTime, ValidationPolicy policy) {
		super(new XmlTLAnalysis());

		result.setCountryCode(currentTL.getCountryCode());

		this.currentTL = currentTL;
		this.currentTime = currentTime;
		this.policy = policy;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlTLAnalysis> item = firstItem = tlFreshness();

		item = item.setNextItem(tlNotExpired());

		item = item.setNextItem(tlVersion());

		item = item.setNextItem(tlWellSigned());

	}

	@Override
	protected void addAdditionalInfo() {
		collectErrorsWarnsInfos();
	}

	private ChainItem<XmlTLAnalysis> tlFreshness() {
		TimeConstraint constraint = policy.getTLFreshnessConstraint();
		return new TLFreshnessCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlNotExpired() {
		LevelConstraint constraint = policy.getTLNotExpiredConstraint();
		return new TLNotExpiredCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlVersion() {
		ValueConstraint constraint = policy.getTLVersionConstraint();
		return new TLVersionCheck(result, currentTL, currentTime, constraint);
	}

	private ChainItem<XmlTLAnalysis> tlWellSigned() {
		LevelConstraint constraint = policy.getTLWellSignedConstraint();
		return new TLWellSignedCheck(result, currentTL, constraint);
	}

}
