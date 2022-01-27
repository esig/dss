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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TSAGeneralNameFieldPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TSAGeneralNameOrderMatchCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.TSAGeneralNameValueMatchCheck;

import java.util.Date;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class TimestampAcceptanceValidation extends AbstractAcceptanceValidation<TimestampWrapper> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date} validation time
	 * @param timestamp {@link TimestampWrapper}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public TimestampAcceptanceValidation(I18nProvider i18nProvider, Date currentTime, TimestampWrapper timestamp,
										 ValidationPolicy validationPolicy) {
		super(i18nProvider, timestamp, currentTime, Context.TIMESTAMP, validationPolicy);
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
	}

	@Override
	protected void initChain() {

		ChainItem<XmlSAV> item = firstItem = signingCertificateAttributePresent();

		// See {@code SignatureAcceptanceValidation.initChain()}
		if (token.isSigningCertificateReferencePresent()) {

			item = item.setNextItem(unicitySigningCertificateAttribute());

			item = item.setNextItem(signingCertificateReferencesValidity());

			item = item.setNextItem(allCertificatesInPathReferenced());

		}

		item = item.setNextItem(tsaGeneralNamePresent());

		if (token.isTSAGeneralNamePresent()) {

			item = item.setNextItem(tsaGeneralNameMatch());

			item = item.setNextItem(tsaGeneralNameOrderMatch());

		}

		item = item.setNextItem(cryptographic());
	}

	private ChainItem<XmlSAV> tsaGeneralNamePresent() {
		LevelConstraint constraint = validationPolicy.getTimestampTSAGeneralNamePresent();
		return new TSAGeneralNameFieldPresentCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> tsaGeneralNameMatch() {
		LevelConstraint constraint = validationPolicy.getTimestampTSAGeneralNameContentMatch();
		return new TSAGeneralNameValueMatchCheck(i18nProvider, result, token, constraint);
	}

	private ChainItem<XmlSAV> tsaGeneralNameOrderMatch() {
		LevelConstraint constraint = validationPolicy.getTimestampTSAGeneralNameOrderMatch();
		return new TSAGeneralNameOrderMatchCheck(i18nProvider, result, token, constraint);
	}

}
