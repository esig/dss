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
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.AbstractTokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

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

	public AbstractAcceptanceValidation(T token, Date currentTime, Context context, ValidationPolicy validationPolicy) {
		super(new XmlSAV());

		this.token = token;
		this.currentTime = currentTime;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	protected ChainItem<XmlSAV> cryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

	@Override
	protected void addAdditionalInfo() {
		super.addAdditionalInfo();

		result.setValidationTime(currentTime);

		XmlCryptographicInformation cryptoInfo = new XmlCryptographicInformation();

		fillAlgorithmURI(cryptoInfo, token);
		cryptoInfo.setKeyLength(token.getKeyLengthUsedToSignThisToken());
		
		XmlConclusion conclusion = result.getConclusion();
		if (Indication.INDETERMINATE.equals(conclusion.getIndication())
				&& (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(conclusion.getSubIndication()))) {
			cryptoInfo.setSecure(false);
		} else {
			cryptoInfo.setSecure(true);
		}

		CryptographicConstraint cryptographicConstraint = validationPolicy.getSignatureCryptographicConstraint(context);
		if (cryptographicConstraint != null) {
			Date notAfter = null;
			CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(cryptographicConstraint);
			Map<String, Date> expirationDates = wrapper.getExpirationTimes();
			String digestAlgoToFind = token.getDigestAlgorithm() == null ? "" : token.getDigestAlgorithm().getName();
			notAfter = expirationDates.get(digestAlgoToFind);
			String encryptionAlgoToFind = token.getEncryptionAlgorithm() == null ? "" : token.getEncryptionAlgorithm().name();
			Date expirationEncryption = expirationDates.get(encryptionAlgoToFind + token.getKeyLengthUsedToSignThisToken());
			if (notAfter == null || (expirationEncryption != null && notAfter.after(expirationEncryption))) {
				notAfter = expirationEncryption;
			}
			cryptoInfo.setNotAfter(notAfter);
		}

		result.setCryptographicInfo(cryptoInfo);
	}

	private void fillAlgorithmURI(XmlCryptographicInformation cryptoInfo, AbstractTokenProxy token) {
		try {
			EncryptionAlgorithm encryptionAlgorithm = token.getEncryptionAlgorithm();
			MaskGenerationFunction maskGenerationFunction = token.getMaskGenerationFunction();
			DigestAlgorithm digestAlgorithm = token.getDigestAlgorithm();
			SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, maskGenerationFunction);
			String uri = sigAlgo.getUri();
			if (uri == null) {
				uri = sigAlgo.getURIBasedOnOID();
			}
			cryptoInfo.setAlgorithm(uri);
		} catch (Exception e) {
			cryptoInfo.setAlgorithm("???");
		}
	}

}
