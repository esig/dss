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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Performs cryptographic validation
 *
 * @param <T> {@code XmlConstraintsConclusion} implementation of the block's conclusion
 */
public abstract class AbstractCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** The cryptographic constraint position to be validated */
	protected final MessageTag position;

	/** Cryptographic Check result */
	protected final XmlCC ccResult;

	/** The checker result message */
	private final XmlMessage checkerResultMessage;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param position {@link MessageTag} cryptographic constrain position
	 * @param ccResult {@link XmlCC}
	 * @param constraint {@link LevelConstraint}
	 */
	protected AbstractCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, MessageTag position,
													  XmlCC ccResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.position = position;
		this.ccResult = ccResult;
		this.checkerResultMessage = extractXmlMessage(ccResult, constraint);
	}
	
	private static XmlMessage extractXmlMessage(XmlCC ccResult, LevelConstraint constraint) {
		XmlConclusion conclusion = ccResult.getConclusion();
		if (conclusion != null && constraint != null && constraint.getLevel() != null) {
			// Collects messages from all levels (required for generic crypto check)
			List<XmlMessage> messages = new ArrayList<>();
			messages.addAll(conclusion.getErrors());
			messages.addAll(conclusion.getWarnings());
			messages.addAll(conclusion.getInfos());
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
	protected Level getLevel() {
		XmlConclusion conclusion = ccResult.getConclusion();
		if (conclusion != null) {
			if (Utils.isCollectionNotEmpty(conclusion.getErrors())) {
				return Level.FAIL;
			} else if (Utils.isCollectionNotEmpty(conclusion.getWarnings())) {
				return Level.WARN;
			} else if (Utils.isCollectionNotEmpty(conclusion.getInfos())) {
				return Level.INFORM;
			}
		}
		return super.getLevel();
	}

	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.ACCM, position);
	}
	
	@Override
	protected XmlMessage buildErrorMessage() {
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
	protected List<XmlMessage> getPreviousErrors() {
		return ccResult.getConclusion().getErrors();
	}

	/**
	 * Gets error message
	 *
	 * @return {@link String}, or empty string if check succeeded
	 */
	protected String getErrorMessage() {
		XmlMessage errorMessage = buildErrorMessage();
		return errorMessage != null ? errorMessage.getValue() : Utils.EMPTY_STRING;
	}

}
