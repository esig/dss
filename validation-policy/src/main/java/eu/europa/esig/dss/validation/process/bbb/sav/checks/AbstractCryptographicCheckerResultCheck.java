package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public abstract class AbstractCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	protected final MessageTag position;
	protected final XmlCC ccResult;
	private final XmlName checkerResultMessage;

	protected AbstractCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, MessageTag position, XmlCC ccResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.position = position;
		this.ccResult = ccResult;
		this.checkerResultMessage = extractXmlNameMessage(ccResult, constraint);
	}
	
	private static XmlName extractXmlNameMessage(XmlCC ccResult, LevelConstraint constraint) {
		XmlConclusion conclusion = ccResult.getConclusion();
		if (conclusion != null && constraint != null && constraint.getLevel() != null) {
			List<XmlName> messages = null;
			switch (constraint.getLevel()) {
				case FAIL:
					messages = conclusion.getErrors();
					break;
				case WARN:
					messages = conclusion.getWarnings();
					break;
				case INFORM:
					messages = conclusion.getInfos();
					break;
				default:
					break;
			}
			
			if (Utils.isCollectionNotEmpty(messages)) {
				return messages.iterator().next(); // take the first one
			}
		}
		return null;
	}

	@Override
	protected boolean process() {
		return isValid(ccResult) && allConstraintsValid(ccResult);
	}
	
	private boolean allConstraintsValid(XmlConstraintsConclusion result) {
		List<XmlConstraint> constraints = result.getConstraint();
		if (Utils.isCollectionNotEmpty(constraints)) {
			for (XmlConstraint constraint : constraints) {
				if (!XmlStatus.OK.equals(constraint.getStatus()) && !XmlStatus.IGNORED.equals(constraint.getStatus())) {
					return false;
				}
			}
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ACCM, position);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return checkerResultMessage;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return ccResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return ccResult.getConclusion().getSubIndication();
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return ccResult.getConclusion().getErrors();
	}
	
	protected String getErrorMessage() {
		return checkerResultMessage != null ? checkerResultMessage.getValue() : Utils.EMPTY_STRING;
	}

}
