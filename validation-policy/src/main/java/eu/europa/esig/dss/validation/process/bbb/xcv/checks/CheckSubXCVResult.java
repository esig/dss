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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Checks if the SubXCV validation result is valid
 */
public class CheckSubXCVResult extends ChainItem<XmlXCV> {

	/** The SubXCV result */
	private final XmlSubXCV subResult;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlXCV}
	 * @param subResult {@link XmlSubXCV}
	 * @param constraint {@link LevelConstraint}
	 */
	public CheckSubXCVResult(I18nProvider i18nProvider, XmlXCV result, XmlSubXCV subResult, LevelConstraint constraint) {
		super(i18nProvider, result, constraint, subResult.getId());
		this.subResult = subResult;
	}

	@Override
	protected boolean process() {
		return isValid(subResult);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_SUB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_SUB_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return subResult.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subResult.getConclusion().getSubIndication();
	}

	@Override
	protected List<XmlName> getPreviousErrors() {
		return subResult.getConclusion().getErrors();
	}

}
