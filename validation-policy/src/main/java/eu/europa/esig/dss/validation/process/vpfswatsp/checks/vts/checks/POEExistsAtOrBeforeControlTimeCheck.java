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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;

import java.util.Date;

/**
 * Checks if a POE exists before the control time
 *
 */
public class POEExistsAtOrBeforeControlTimeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Token to check */
	private final TokenProxy token;

	/** The object's type */
	private final TimestampedObjectType referenceCategory;

	/** Control time to check against */
	private final Date controlTime;

	/** POE container */
	private final POEExtraction poe;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param token {@link TokenProxy}
	 * @param referenceCategory {@link TimestampedObjectType}
	 * @param controlTime {@link Date}
	 * @param poe {@link POEExtraction}
	 * @param constraint {@link LevelConstraint}
	 */
	public POEExistsAtOrBeforeControlTimeCheck(I18nProvider i18nProvider, T result, TokenProxy token,
											   TimestampedObjectType referenceCategory, Date controlTime,
											   POEExtraction poe, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.token = token;
		this.referenceCategory = referenceCategory;
		this.controlTime = controlTime;
		this.poe = poe;
	}

	@Override
	protected boolean process() {
		return poe.isPOEExists(token.getId(), controlTime);
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.CONTROL_TIME, token.getId(), ValidationProcessUtils.getFormattedDate(controlTime));
	}

	@Override
	protected MessageTag getMessageTag() {
		if (TimestampedObjectType.CERTIFICATE.equals(referenceCategory)) {
			return MessageTag.PSV_ITPOCOBCT;
		} else if (TimestampedObjectType.REVOCATION.equals(referenceCategory)) {
			return MessageTag.PSV_ITPORDAOBCT;
		}
		throw new IllegalStateException("Problem VTS");
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_ITPOOBCT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_POE;
	}

}
