package eu.europa.esig.dss.EN319102.bbb;

import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlError;
import eu.europa.esig.dss.jaxb.detailedreport.XmlInfo;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public abstract class ChainItem<T extends XmlConstraintsConclusion> {

	private static final Logger logger = LoggerFactory.getLogger(ChainItem.class);

	private ChainItem<T> nextItem;

	private T result;

	private final LevelConstraint constraint;

	private String bbbId;
	
	private List<XmlInfo> infos = new ArrayList<XmlInfo>();

	protected ChainItem(T result, LevelConstraint constraint) {
		this.result = result;
		this.constraint = constraint;
	}

	protected ChainItem(T result, LevelConstraint constraint, String bbbId) {
		this.result = result;
		this.constraint = constraint;
		this.bbbId = bbbId;
	}

	public ChainItem<T> setNextItem(ChainItem<T> nextItem) {
		this.nextItem = nextItem;
		return nextItem;
	}

	public void execute() {
		if (constraint == null) {
			logger.info("Check skipped : constraint not defined");
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
	
	public void addInfo(XmlInfo info) {
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

	private void recordConclusion() {
		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(getFailedIndicationForConclusion());
		conclusion.setSubIndication(getFailedSubIndicationForConclusion());
		XmlError errorMessage = new XmlError();
		MessageTag errorMessageTag = getErrorMessageTag();
		errorMessage.setNameId(errorMessageTag.name());
		errorMessage.setValue(errorMessageTag.getMessage());
		conclusion.setError(errorMessage);
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
		constraint.getInfo().addAll(infos);
		addConstraint(constraint);
	}

	private void addConstraint(XmlConstraint constraint) {
		result.getConstraints().add(constraint);
	}

	private XmlName buildConstraintName() {
		MessageTag tag = getMessageTag();
		XmlName name = new XmlName();
		name.setNameId(tag.name());
		name.setValue(tag.getMessage());
		return name;
	}

	/**
	 * This method skips next elements
	 */
	private void fail() {
		boolean valid = process();
		if (valid) {
			recordValid();
			callNext();
		} else {
			recordInvalid();
			recordConclusion();
		}
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

}
