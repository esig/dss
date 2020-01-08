package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import java.text.MessageFormat;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;

public class RevocationAcceptanceCheckerResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final XmlRAC racResult;

	public RevocationAcceptanceCheckerResultCheck(I18nProvider i18nProvider, T result, XmlRAC racResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.racResult = racResult;
	}

	@Override
	protected boolean process() {
		return isValid(racResult);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_RAC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_RAC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return racResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return racResult.getConclusion().getSubIndication();
	}
	
	@Override
	protected String getAdditionalInfo() {
		if (racResult.getRevocationProductionDate() != null) {
			String addInfo = AdditionalInfo.REVOCATON_ACCEPTANCE_CHECK;
			Object[] params = new Object[] { racResult.getId(), convertDate(racResult.getRevocationProductionDate()) };
			return MessageFormat.format(addInfo, params);
		}
		return null;
	}

}
