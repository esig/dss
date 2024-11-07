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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Validates Digest cryptographic constraint
 *
 * @param <T> {@code XmlConstraintsConclusion} implementation of the block's conclusion
 */
public class DigestCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheckerResultCheck<T> {

	/** Validation time */
	protected final Date validationDate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param ccResult {@link XmlCC}
	 * @param constraint {@link LevelConstraint}
	 */
	public DigestCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate,
												 MessageTag position, XmlCC ccResult, LevelConstraint constraint) {
		super(i18nProvider, result, position, ccResult, constraint);
		this.validationDate = validationDate;
	}
	
	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (isValid(ccResult)) {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM,
					ccResult.getVerifiedAlgorithm().getName(), dateTime, position);
		} else {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF,
					getErrorMessage(), dateTime);
		}
	}

}
