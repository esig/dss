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

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicChecker;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicInformationBuilder;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestCryptographicChecker;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestCryptographicCheckerResultCheck;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public abstract class AbstractAcceptanceValidation<T extends AbstractTokenProxy> extends Chain<XmlSAV> {

	protected final T token;
	protected final Date currentTime;
	protected final Context context;
	protected final ValidationPolicy validationPolicy;
	
	private CryptographicInformationBuilder cryptographicInformationBuilder;

	protected AbstractAcceptanceValidation(I18nProvider i18nProvider, T token, Date currentTime, Context context, ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlSAV());

		this.token = token;
		this.currentTime = currentTime;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	protected ChainItem<XmlSAV> cryptographic() {
		ChainItem<XmlSAV> firstItem;
		
		// The basic signature constraints validation
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		MessageTag position = ValidationProcessUtils.getCryptoPosition(context);
		
		CryptographicChecker cc = new CryptographicChecker(i18nProvider, token, currentTime, position, constraint);
		XmlCC ccResult = cc.execute();
		
		ChainItem<XmlSAV> item = firstItem = cryptographicCheckResult(ccResult, position, constraint);
		
		cryptographicInformationBuilder = new CryptographicInformationBuilder(token, ccResult.getConclusion(), constraint);
		
		if (!isValid(ccResult)) {
			// return if not valid
			return firstItem;
		}
		
		// process digestMatchers
		List<XmlDigestMatcher> digestMatchers = token.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				DigestAlgorithm digestAlgorithm = digestMatcher.getDigestMethod();
				if (digestAlgorithm == null) {
					continue;
				}
				
				position = ValidationProcessUtils.getDigestMatcherCryptoPosition(digestMatcher);
				DigestCryptographicChecker dac = new DigestCryptographicChecker(i18nProvider, digestAlgorithm, currentTime, position, constraint);
				XmlCC dacResult = dac.execute();
				
				item = item.setNextItem(digestAlgorithmCheckResult(digestMatcher, dacResult, position, constraint));
				
				if (!isValid(dacResult)) {
					// update the failed constraints and brake the loop
					cryptographicInformationBuilder = new CryptographicInformationBuilder(digestMatcher, dacResult.getConclusion(), constraint);
					break;
				}
			}
		}
		
		return firstItem;
	}
	
	private ChainItem<XmlSAV> cryptographicCheckResult(XmlCC ccResult, MessageTag position, CryptographicConstraint constraint) {
		return new CryptographicCheckerResultCheck<>(i18nProvider, result, token, currentTime, position, ccResult, constraint);
	}
	
	private ChainItem<XmlSAV> digestAlgorithmCheckResult(XmlDigestMatcher digestMatcher, XmlCC ccResult, 
			MessageTag position, CryptographicConstraint constraint) {
		return new DigestCryptographicCheckerResultCheck<>(i18nProvider, result, currentTime, position, digestMatcher.getName(), ccResult, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		super.addAdditionalInfo();
		
		result.setValidationTime(currentTime);
		result.setCryptographicInfo(cryptographicInformationBuilder.build());
	}

}
