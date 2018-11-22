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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataFreshCheckWithNullConstraint extends ChainItem<XmlRFC> {

	private final RevocationWrapper revocationData;
	private final Date validationDate;

	public RevocationDataFreshCheckWithNullConstraint(XmlRFC result, RevocationWrapper revocationData, Date validationDate, LevelConstraint constraint) {
		super(result, constraint);

		this.revocationData = revocationData;
		this.validationDate = validationDate;
	}

	@Override
	protected boolean process() {
		if (revocationData != null && revocationData.getNextUpdate() != null) {
			long maxFreshness = getMaxFreshness();
			long validationDateTime = validationDate.getTime();
			long limit = validationDateTime - maxFreshness;

			Date productionDate = revocationData.getProductionDate();
			return productionDate != null && productionDate.after(new Date(limit));
		}
		return false;
	}

	private long getMaxFreshness() {
		return diff(revocationData.getNextUpdate(), revocationData.getThisUpdate());
	}

	private long diff(Date nextUpdate, Date thisUpdate) {
		long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
		long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
		return nextUpdateTime - thisUpdateTime;
	}

	@Override
	protected String getAdditionalInfo() {
		String nextUpdateString = "not defined";
		if (revocationData != null && revocationData.getNextUpdate() != null) {
			SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
			sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
			nextUpdateString = sdf.format(revocationData.getNextUpdate());
		}
		Object[] params = new Object[] { nextUpdateString };
		return MessageFormat.format(AdditionalInfo.NEXT_UPDATE, params);
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
