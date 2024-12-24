/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.List;

/**
 * This class is part of the design pattern "Chain of responsibility".
 * 
 * All sub-classes need to implement the method initChain() which will define the {@code ChainItem} (constraints) to
 * execute.
 * 
 * The chain is built as follows with the method {@link eu.europa.esig.dss.validation.process.ChainItem#setNextItem}.
 * 
 * @param <T>
 *            the class used as result. The selected class must extend {@code XmlConstraintsConclusion} which contains
 *            some constraints and a conclusion.
 * 
 * @see ChainItem
 */
public abstract class Chain<T extends XmlConstraintsConclusion> {

	/**
	 * The result object : a sub-class of {@code XmlConstraintsConclusion}
	 */
	protected final T result;
	
	/**
	 * Internationalization provider
	 */
	protected final I18nProvider i18nProvider;

	/**
	 * The first item to execute the chain
	 */
	protected ChainItem<T> firstItem;

	/**
	 * Common constructor
	 * 
	 * @param i18nProvider the access to translations
	 * @param newInstance  a new instance of the result object
	 */
	protected Chain(I18nProvider i18nProvider, T newInstance) {
		this.i18nProvider = i18nProvider;
		this.result = newInstance;
	}

	/**
	 * This method allows initialization and execution of complete chain until the first failure.
	 * 
	 * @return the complete result with constraints and final conclusion for the chain
	 */
	public T execute() {
		initChain();

		if (firstItem != null) {
			firstItem.execute();
		}
		
		result.setTitle(buildChainTitle());

		if (result.getConclusion() == null) {
			XmlConclusion conclusion = new XmlConclusion();
			conclusion.setIndication(Indication.PASSED);
			result.setConclusion(conclusion);
		}

		collectMessages();
		addAdditionalInfo();

		return result;
	}

	/**
	 * Builds the chain title
	 *
	 * @return {@link String} chain title
	 */
	protected String buildChainTitle() {
		return ValidationProcessUtils.buildStringMessage(i18nProvider, getTitle());
	}
	
	/**
	 * Returns title of a Chain (i.e. BasicBuildingBlock title)
	 *
	 * @return {@link MessageTag}
	 */
	protected MessageTag getTitle() {
		return null;
	}

	/**
	 * Adds additional info to the chain
	 */
	protected void addAdditionalInfo() {
		// default is empty
	}

	/**
	 * Initializes the chain
	 */
	protected abstract void initChain();

	/**
	 * Checks if the {@code constraintConclusion} has a successful validation result
	 *
	 * @param constraintConclusion {@link XmlConstraintsConclusion}
	 * @return TRUE if the conclusion is valid, FALSE otherwise
	 */
	protected boolean isValid(XmlConstraintsConclusion constraintConclusion) {
		return constraintConclusion != null && isValidConclusion(constraintConclusion.getConclusion());
	}

	/**
	 * Checks if the conclusion is valid
	 *
	 * @param conclusion {@link XmlConclusion}
	 * @return TRUE if the conclusion has a PASSED Indication, FALSE otherwise
	 */
	protected boolean isValidConclusion(XmlConclusion conclusion) {
		return conclusion != null && Indication.PASSED.equals(conclusion.getIndication());
	}

	/**
	 * Returns the FAIL level constraint
	 *
	 * @return {@link LevelConstraint}
	 */
	protected LevelConstraint getFailLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		return constraint;
	}

	/**
	 * Returns the WARN level constraint
	 *
	 * @return {@link LevelConstraint}
	 */
	protected LevelConstraint getWarnLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		return constraint;
	}

	/**
	 * Returns the INFO level constraint
	 *
	 * @return {@link LevelConstraint}
	 */
	protected LevelConstraint getInfoLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.INFORM);
		return constraint;
	}

	/**
	 * Collects all required messages
	 */
	private void collectMessages() {
		XmlConclusion conclusion = result.getConclusion();
		
		List<XmlConstraint> constraints = result.getConstraint();
		for (XmlConstraint constraint : constraints) {
			collectMessages(conclusion, constraint);
		}
		collectAdditionalMessages(conclusion);
	}

	/**
	 * Collects required messages from {@code xmlConstraint} to the given {@code conclusion}
	 *
	 * NOTE: bye default the only one error is already collected in the chain (no more possible),
	 *       therefore no need to collect it again
	 *
	 * @param conclusion {@link XmlConclusion} to fill up
	 * @param constraint {@link XmlConstraint} to extract messages from
	 */
	protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
		XmlMessage warning = constraint.getWarning();
		if (warning != null) {
			conclusion.getWarnings().add(warning);
		}
		XmlMessage info = constraint.getInfo();
		if (info != null) {
			conclusion.getInfos().add(info);
		}
	}

	/**
	 * Fills all messages from {@code conclusionToFillFrom} into {@code conclusionToFill}
	 *
	 * @param conclusionToFill {@link XmlConclusion} to be filled
	 * @param conclusionToFillFrom {@link XmlConclusion} to fill from
	 */
	protected void collectAllMessages(XmlConclusion conclusionToFill, XmlConclusion conclusionToFillFrom) {
		List<XmlMessage> errors = conclusionToFillFrom.getErrors();
		if (errors != null) {
			conclusionToFill.getErrors().addAll(errors);
		}
		List<XmlMessage> warnings = conclusionToFillFrom.getWarnings();
		if (warnings != null) {
			conclusionToFill.getWarnings().addAll(warnings);
		}
		List<XmlMessage> infos = conclusionToFillFrom.getInfos();
		if (infos != null) {
			conclusionToFill.getInfos().addAll(infos);
		}
	}

	/**
	 * The method allows to fill up additional messages into the conclusion
	 *
	 * @param conclusion {@link XmlConclusion} to fill up
	 */
	protected void collectAdditionalMessages(XmlConclusion conclusion) {
		// empty by default
	}

}
