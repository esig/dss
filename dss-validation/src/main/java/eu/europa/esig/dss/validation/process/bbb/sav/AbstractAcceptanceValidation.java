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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicValidation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicChecker;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestMatcherListCryptographicChainBuilder;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.SigningCertificateRefDigestAlgorithmCheckChainBuilder;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.AllCertificatesInPathReferencedCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningCertificateAttributePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.SigningCertificateReferencesValidityCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.UnicitySigningCertificateAttributeCheck;

import java.util.Date;
import java.util.List;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 *
 * @param <T> validation token wrapper
 */
public abstract class AbstractAcceptanceValidation<T extends AbstractTokenProxy> extends Chain<XmlSAV> {

	/** The token to be validated */
	protected final T token;

	/** The validation time */
	protected final Date currentTime;

	/** The validation context */
	protected final Context context;

	/** The validation policy */
	protected final ValidationPolicy validationPolicy;

	/** The cryptographic information for the report */
	private XmlCryptographicValidation cryptographicValidation;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token to validate
	 * @param currentTime {@link Date}
	 * @param context {@link Context}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	protected AbstractAcceptanceValidation(I18nProvider i18nProvider, T token, Date currentTime, Context context,
										ValidationPolicy validationPolicy) {
		super(i18nProvider, new XmlSAV());
		this.token = token;
		this.currentTime = currentTime;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	/**
	 * Checks whether a signing-certificate signed attribute is present
	 *
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> signingCertificateAttributePresent() {
		LevelRule constraint = validationPolicy.getSigningCertificateAttributePresentConstraint(context);
		return new SigningCertificateAttributePresentCheck(i18nProvider, result, token, constraint);
	}

	/**
	 * Checks if only one signing-certificate signed attribute is present
	 *
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> unicitySigningCertificateAttribute() {
		LevelRule constraint = validationPolicy.getUnicitySigningCertificateAttributeConstraint(context);
		return new UnicitySigningCertificateAttributeCheck(i18nProvider, result, token, constraint);
	}

	/**
	 * Checks whether a signing-certificate signed attribute is valid to the determined signing certificate
	 *
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> signingCertificateReferencesValidity() {
		LevelRule constraint = validationPolicy.getSigningCertificateRefersCertificateChainConstraint(context);
		return new SigningCertificateReferencesValidityCheck(i18nProvider, result, token, constraint);
	}

	/**
	 * Checks if all certificates in a signing certificate chain are references
	 * within signing-certificate signed attribute
	 *
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> allCertificatesInPathReferenced() {
		LevelRule constraint = validationPolicy.getReferencesToAllCertificateChainPresentConstraint(context);
		return new AllCertificatesInPathReferencedCheck(i18nProvider, result, token, constraint);
	}

	/**
	 * Verifies cryptographic validity of signature references and signing-certificate signed attribute
	 *
	 * @param item {@link ChainItem} the last initialized chain item to be processed
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> cryptographic(ChainItem<XmlSAV> item) {
		// The basic signature constraints validation
		CryptographicSuite constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		MessageTag position = ValidationProcessUtils.getCryptoPosition(context);
		
		CryptographicChecker cc = new CryptographicChecker(i18nProvider, token, currentTime, position, constraint);
		XmlCC ccResult = cc.execute();

		if (item == null) {
			item = firstItem = cryptographicCheckResult(ccResult, position, constraint);
		} else {
			item = item.setNextItem(cryptographicCheckResult(ccResult, position, constraint));
		}

		cryptographicValidation = getCryptographicValidation(ccResult);
		cryptographicValidation.setConcernedMaterial(token.getId());
		
		if (!isValid(ccResult)) {
			// return if not valid
			return item;
		}
		
		// process digestMatchers
		List<XmlDigestMatcher> digestMatchers = token.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			DigestMatcherListCryptographicChainBuilder<XmlSAV> digestMatcherCCBuilder =
					new DigestMatcherListCryptographicChainBuilder<>(i18nProvider, result, digestMatchers, currentTime, constraint);
			item = digestMatcherCCBuilder.build(item);

			XmlCC failedCC = digestMatcherCCBuilder.getConcernedCC();
			if (failedCC != null && !isValid(failedCC)) {
				cryptographicValidation = getCryptographicValidation(failedCC);
				List<String> failedMaterial = digestMatcherCCBuilder.getConcernedMaterial();
				cryptographicValidation.setConcernedMaterial(getConcernedMaterialDescription(failedMaterial, position));
			}
		}
		
		return item;
	}

	/**
	 * This method verifies the validity of the used cryptographic constraints for signed-attributes
	 *
	 * @param item {@link ChainItem} the last initialized chain item to be processed
	 * @return {@link ChainItem}
	 */
	protected ChainItem<XmlSAV> cryptographicSignedAttributes(ChainItem<XmlSAV> item) {
		final SigningCertificateRefDigestAlgorithmCheckChainBuilder<XmlSAV> chainBuilder =
				new SigningCertificateRefDigestAlgorithmCheckChainBuilder<>(i18nProvider, result, currentTime, token, context, validationPolicy);

		item = chainBuilder.build(item);

		XmlCryptographicValidation signCertRefDigestAlgoValidation = chainBuilder.getCryptographicValidation();

		// overwrite only if previous checks are secure
		if ((cryptographicValidation == null || cryptographicValidation.isSecure())
				&& (signCertRefDigestAlgoValidation != null && !signCertRefDigestAlgoValidation.isSecure())) {
			cryptographicValidation = signCertRefDigestAlgoValidation;
		}

		return item;
	}
	
	private ChainItem<XmlSAV> cryptographicCheckResult(XmlCC ccResult, MessageTag position, CryptographicSuite constraint) {
		return new CryptographicCheckerResultCheck<>(i18nProvider, result, currentTime, position, ccResult, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		super.addAdditionalInfo();

		result.setCryptographicValidation(cryptographicValidation);
	}

	private XmlCryptographicValidation getCryptographicValidation(XmlCC ccResult) {
		XmlCryptographicValidation xmlCryptographicValidation = new XmlCryptographicValidation();
		xmlCryptographicValidation.setAlgorithm(ccResult.getVerifiedAlgorithm());
		xmlCryptographicValidation.setNotAfter(ccResult.getNotAfter());
		xmlCryptographicValidation.setSecure(isValid(ccResult));
		xmlCryptographicValidation.setValidationTime(currentTime);
		return xmlCryptographicValidation;
	}

	private String getConcernedMaterialDescription(List<String> referenceNames, MessageTag position) {
		if (Utils.isCollectionNotEmpty(referenceNames)) {
			return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_NAME, position, Utils.joinStrings(referenceNames, ", "));
		}
		return i18nProvider.getMessage(position);
	}

}
