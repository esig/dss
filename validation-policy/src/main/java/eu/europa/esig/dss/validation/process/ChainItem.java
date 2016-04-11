package eu.europa.esig.dss.validation.process;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * This class is an item of the {@code Chain} class.
 *
 * That follows the design pattern "chain of responsibility".
 * 
 * Depending of the {@code Level} in {@code LevelConstraint} the Chain will continue/stop the current treatment. The {@code ChainItem} is a validation
 * constraint which allows to collect information, warnings, errors,...
 * 
 * @see Chain
 */
public abstract class ChainItem<T extends XmlConstraintsConclusion> {

	private static final Logger logger = LoggerFactory.getLogger(ChainItem.class);

	private ChainItem<T> nextItem;

	private T result;

	private final LevelConstraint constraint;

	private String bbbId;

	private List<String> infos = new ArrayList<String>();

	/**
	 * Common constructor
	 * 
	 * @param result
	 *            the {@code Chain} object parent of this object
	 * @param constraint
	 *            the {@code LevelConstraint} to follow to execute this ChainItem
	 * 
	 */
	protected ChainItem(T result, LevelConstraint constraint) {
		this.result = result;
		this.constraint = constraint;
	}

	/**
	 * Specific constructor for Basic Building Blocks validation
	 * 
	 * @param result
	 *            the {@code Chain} object parent of this object
	 * @param constraint
	 *            the {@code LevelConstraint} to follow to execute this ChainItem
	 * @param bbbId
	 *            the {@code XmlBasicBuildingBlocks}'s id
	 * 
	 */
	protected ChainItem(T result, LevelConstraint constraint, String bbbId) {
		this.result = result;
		this.constraint = constraint;
		this.bbbId = bbbId;
	}

	/**
	 * This method allows to build the chain of responsibility
	 * 
	 * @param nextItem
	 *            the next {@code ChainItem} to call if this one succeed
	 * @return the current item
	 */
	public ChainItem<T> setNextItem(ChainItem<T> nextItem) {
		this.nextItem = nextItem;
		return nextItem;
	}

	/**
	 * This method allows to execute the chain of responsibility. It will run all the chain until the first {@code Level.FAIL} and not valid process.
	 */
	public void execute() {
		if ((constraint == null) || (constraint.getLevel() == null)) {
			logger.trace("Check skipped : constraint not defined");
			callNext();
		} else {
			switch (constraint.getLevel()) {
			case IGNORE:
				ignore();
				break;
			case FAIL:
				fail();
				break;
			case INFORM:
			case WARN:
				informOrWarn(constraint.getLevel());
				break;
			default:
				logger.warn("Unknown level : " + constraint.getLevel());
				break;
			}
		}
	}

	protected void addInfo(String info) {
		infos.add(info);
	}

	protected abstract boolean process();

	protected abstract MessageTag getMessageTag();

	protected abstract MessageTag getErrorMessageTag();

	protected abstract Indication getFailedIndicationForConclusion();

	protected abstract SubIndication getFailedSubIndicationForConclusion();

	private void recordIgnore() {
		recordConstraint(XmlStatus.IGNORED);
	}

	private void recordValid() {
		recordConstraint(XmlStatus.OK);
	}

	private void recordInvalid() {
		recordConstraint(XmlStatus.NOT_OK);
	}

	private void recordCustomSuccessConclusion() {
		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(getSuccessIndication());
		conclusion.setSubIndication(getSuccessSubIndication());
		result.setConclusion(conclusion);
	}

	private void recordConclusion() {
		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(getFailedIndicationForConclusion());
		conclusion.setSubIndication(getFailedSubIndicationForConclusion());
		XmlName errorMessage = new XmlName();
		MessageTag errorMessageTag = getErrorMessageTag();
		if (errorMessageTag != null) {
			errorMessage.setNameId(errorMessageTag.name());
			errorMessage.setValue(errorMessageTag.getMessage());
		} else {
			logger.error("MessageTag is not defined!");
		}
		conclusion.getErrors().add(errorMessage);
		result.setConclusion(conclusion);
	}

	private void recordInfosOrWarns(Level level) {
		if (Level.INFORM.equals(level)) {
			recordConstraint(XmlStatus.INFORMATION);
		} else if (Level.WARN.equals(level)) {
			recordConstraint(XmlStatus.WARNING);
		}
	}

	private void recordConstraint(XmlStatus status) {
		XmlConstraint constraint = new XmlConstraint();
		constraint.setName(buildConstraintName());
		constraint.setStatus(status);
		constraint.setId(bbbId);
		if (XmlStatus.NOT_OK.equals(status) || XmlStatus.WARNING.equals(status) || XmlStatus.INFORMATION.equals(status)) {
			XmlName message = new XmlName();
			MessageTag errorMessageTag = getErrorMessageTag();
			if (errorMessageTag != null) {
				message.setNameId(errorMessageTag.name());
				message.setValue(errorMessageTag.getMessage());
			} else {
				logger.error("MessageTag is not defined!");
			}
			if (XmlStatus.NOT_OK.equals(status)) {
				constraint.setError(message);
			} else if (XmlStatus.WARNING.equals(status)) {
				constraint.setWarning(message);
			} else if (XmlStatus.INFORMATION.equals(status)) {
				constraint.setInfo(message);
			}
		}
		addConstraint(constraint);
	}

	private void addConstraint(XmlConstraint constraint) {
		result.getConstraint().add(constraint);
	}

	private XmlName buildConstraintName() {
		MessageTag tag = getMessageTag();
		XmlName name = new XmlName();
		if (tag != null) {
			name.setNameId(tag.name());
			name.setValue(tag.getMessage());
		} else {
			logger.error("MessageTag is not defined!");
		}
		return name;
	}

	/**
	 * This method skips next elements
	 */
	private void fail() {
		boolean valid = process();
		if (valid) {
			recordValid();
			if (!isCustomSuccessConclusion()) {
				callNext();
			} else {
				recordCustomSuccessConclusion();
			}
		} else {
			recordInvalid();
			recordConclusion();
		}
	}

	private boolean isCustomSuccessConclusion() {
		return getSuccessIndication() != null;
	}

	protected Indication getSuccessIndication() {
		return null;
	}

	protected SubIndication getSuccessSubIndication() {
		return null;
	}

	private void informOrWarn(Level level) {
		boolean valid = process();
		if (valid) {
			recordValid();
		} else {
			recordInfosOrWarns(level);
		}
		callNext();
	}

	private void ignore() {
		recordIgnore();
		callNext();
	}

	private void callNext() {
		if (nextItem != null) {
			nextItem.execute();
		}
	}

	protected boolean isValid(XmlConstraintsConclusion constraintConclusion) {
		return constraintConclusion != null && constraintConclusion.getConclusion() != null
				&& Indication.PASSED.equals(constraintConclusion.getConclusion().getIndication());
	}

}
