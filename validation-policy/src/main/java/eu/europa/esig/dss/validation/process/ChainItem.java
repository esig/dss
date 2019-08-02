/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process;

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class is an item of the {@code Chain} class.
 *
 * That follows the design pattern "chain of responsibility".
 * 
 * Depending of the {@code Level} in {@code LevelConstraint} the Chain will continue/stop the current treatment. The
 * {@code ChainItem} is a validation
 * constraint which allows to collect information, warnings, errors,...
 * 
 * @see Chain
 */
public abstract class ChainItem<T extends XmlConstraintsConclusion> {

	private static final Logger LOG = LoggerFactory.getLogger(ChainItem.class);

	private ChainItem<T> nextItem;

	private T result;

	private final LevelConstraint constraint;

	private String bbbId;

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
	 * This method allows to execute the chain of responsibility. It will run all the chain until the first
	 * {@code Level.FAIL} and not valid process.
	 */
	public void execute() {
		if ((constraint == null) || (constraint.getLevel() == null)) {
			LOG.trace("Check skipped : constraint not defined");
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
				LOG.warn("Unknown level : {}", constraint.getLevel());
				break;
			}
		}
	}

	protected abstract boolean process();

	protected abstract IMessageTag getMessageTag();

	protected abstract IMessageTag getErrorMessageTag();

	protected List<XmlName> getPreviousErrors() {
		return Collections.emptyList();
	}

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

		List<XmlName> previousErrors = getPreviousErrors();
		if (Utils.isCollectionNotEmpty(previousErrors)) {
			conclusion.getErrors().addAll(previousErrors);
		} else {
			conclusion.getErrors().add(buildXmlName(getErrorMessageTag()));
		}

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
		XmlConstraint xmlConstraint = new XmlConstraint();
		xmlConstraint.setName(buildXmlName(getMessageTag()));
		xmlConstraint.setStatus(status);
		xmlConstraint.setId(bbbId);
		if (XmlStatus.NOT_OK.equals(status) || XmlStatus.WARNING.equals(status) || XmlStatus.INFORMATION.equals(status)) {
			if (XmlStatus.NOT_OK.equals(status)) {
				xmlConstraint.setError(buildXmlName(getErrorMessageTag()));
			} else if (XmlStatus.WARNING.equals(status)) {
				xmlConstraint.setWarning(buildXmlName(getErrorMessageTag()));
			} else if (XmlStatus.INFORMATION.equals(status)) {
				xmlConstraint.setInfo(buildXmlName(getErrorMessageTag()));
			}
		}
		if (!XmlStatus.IGNORED.equals(status)) {
			xmlConstraint.setAdditionalInfo(getAdditionalInfo());
		}
		addConstraint(xmlConstraint);
	}

	protected String getAdditionalInfo() {
		return null;
	}

	private void addConstraint(XmlConstraint constraint) {
		result.getConstraint().add(constraint);
	}

	private XmlName buildXmlName(IMessageTag messageTag) {
		XmlName xmlName = new XmlName();
		if (messageTag != null) {
			xmlName.setNameId(messageTag.getId());
			xmlName.setValue(messageTag.getMessage());
		} else {
			LOG.error("MessageTag is null");
		}
		return xmlName;
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
		return constraintConclusion != null && isValidConclusion(constraintConclusion.getConclusion());
	}

	protected boolean isValidConclusion(XmlConclusion conclusion) {
		return conclusion != null && Indication.PASSED.equals(conclusion.getIndication());
	}

	protected boolean isInvalidConclusion(XmlConclusion conclusion) {
		return conclusion != null && Indication.FAILED.equals(conclusion.getIndication());
	}

	protected boolean isIndeterminateConclusion(XmlConclusion conclusion) {
		return conclusion != null && Indication.INDETERMINATE.equals(conclusion.getIndication());
	}

	protected boolean isAcceptableConclusion(XmlConclusion conclusion) {
		return conclusion != null && !Indication.FAILED.equals(conclusion.getIndication());
	}

}
