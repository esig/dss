package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

public class LatestRevocationAcceptanceCheckerResultCheck<T extends XmlConstraintsConclusion> extends RevocationAcceptanceCheckerResultCheck<T> {
	
	public LatestRevocationAcceptanceCheckerResultCheck(I18nProvider i18nProvider, T result, XmlRAC racResult,
			LevelConstraint constraint) {
		super(i18nProvider, result, racResult, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC_ANS;
	}

}
