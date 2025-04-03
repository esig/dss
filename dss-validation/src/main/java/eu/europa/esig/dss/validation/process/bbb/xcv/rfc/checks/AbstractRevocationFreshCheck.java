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
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Abstract revocation check class
 */
public abstract class AbstractRevocationFreshCheck extends ChainItem<XmlRFC> {

	/** Revocation data to check */
	protected final RevocationWrapper revocationData;

	/** Validation time */
	private final Date validationDate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlRFC}
	 * @param revocationData {@link RevocationWrapper}
	 * @param validationDate {@link Date}
	 * @param constraint {@link LevelRule}
	 */
	protected AbstractRevocationFreshCheck(I18nProvider i18nProvider, XmlRFC result, RevocationWrapper revocationData, 
			Date validationDate, LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.revocationData = revocationData;
		this.validationDate = validationDate;
	}

	/**
	 * Returns if the revocation production data is after validation time with the allowed freshness
	 *
	 * @return TRUE is revocation is after validation time, FALSE otherwise
	 */
	protected boolean isThisUpdateTimeAfterValidationTime() {
		long maxFreshness = getMaxFreshness();
		long validationDateTime = validationDate.getTime();
		long limit = validationDateTime - maxFreshness;

		Date thisUpdate = revocationData.getThisUpdate();
		return thisUpdate != null && thisUpdate.after(new Date(limit));
	}

	/**
	 * Returns the maximum freshness
	 *
	 * @return maximum freshness
	 */
	protected abstract long getMaxFreshness();

	@Override
	protected String buildAdditionalInfo() {
		String thisUpdateString = "not defined";
		String nextUpdateString = "not defined";
		if (revocationData != null) {
			if (revocationData.getThisUpdate() != null)
				thisUpdateString = ValidationProcessUtils.getFormattedDate(revocationData.getThisUpdate());
			if (revocationData.getNextUpdate() != null)
				nextUpdateString = ValidationProcessUtils.getFormattedDate(revocationData.getNextUpdate());
		}
		return i18nProvider.getMessage(MessageTag.REVOCATION_CHECK, ValidationProcessUtils.getFormattedDate(validationDate), thisUpdateString,
				nextUpdateString);
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