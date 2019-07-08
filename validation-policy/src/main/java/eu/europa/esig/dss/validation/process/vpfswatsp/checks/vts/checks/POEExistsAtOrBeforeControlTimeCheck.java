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

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class POEExistsAtOrBeforeControlTimeCheck extends ChainItem<XmlVTS> {

	private final TokenProxy token;
	private final TimestampedObjectType referenceCategory;
	private final Date controlTime;
	private final POEExtraction poe;

	public POEExistsAtOrBeforeControlTimeCheck(XmlVTS result, TokenProxy token, TimestampedObjectType referenceCategory, Date controlTime, POEExtraction poe,
			LevelConstraint constraint) {
		super(result, constraint);

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
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		Object[] params = new Object[] { sdf.format(controlTime) };
		return MessageFormat.format(AdditionalInfo.CONTROL_TIME, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		if (TimestampedObjectType.CERTIFICATE.equals(referenceCategory)) {
			return MessageTag.PSV_ITPOCOBCT;
		} else if (TimestampedObjectType.REVOCATION.equals(referenceCategory)) {
			return MessageTag.PSV_ITPORDAOBCT;
		}
		throw new DSSException("Problem VTS");
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
