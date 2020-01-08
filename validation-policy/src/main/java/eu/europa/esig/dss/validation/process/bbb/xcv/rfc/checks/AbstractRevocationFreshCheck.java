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
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import java.text.MessageFormat;
import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;

public abstract class AbstractRevocationFreshCheck extends ChainItem<XmlRFC> {

	protected final RevocationWrapper revocationData;
	private final Date validationDate;

	protected AbstractRevocationFreshCheck(I18nProvider i18nProvider, XmlRFC result, RevocationWrapper revocationData, 
			Date validationDate, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.revocationData = revocationData;
		this.validationDate = validationDate;
	}
	
	protected boolean isProductionDateNotBeforeValidationTime() {
		long maxFreshness = getMaxFreshness();
		long validationDateTime = validationDate.getTime();
		long limit = validationDateTime - maxFreshness;

		Date productionDate = revocationData.getProductionDate();
		return productionDate != null && productionDate.after(new Date(limit));
	}

	protected abstract long getMaxFreshness();

	@Override
	protected String getAdditionalInfo() {
		String productionTimeString = "not defined";
		String nextUpdateString = "not defined";
		if (revocationData != null) {
			if (revocationData.getProductionDate() != null)
				productionTimeString = convertDate(revocationData.getProductionDate());
			if (revocationData.getNextUpdate() != null)
				nextUpdateString = convertDate(revocationData.getNextUpdate());
		}
		Object[] params = new Object[] { convertDate(validationDate), productionTimeString, nextUpdateString };
		return MessageFormat.format(AdditionalInfo.REVOCATION_CHECK, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_RFC_IRIF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_RFC_IRIF_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

}