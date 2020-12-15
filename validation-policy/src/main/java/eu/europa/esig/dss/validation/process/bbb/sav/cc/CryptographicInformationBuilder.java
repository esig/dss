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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicInformation;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Date;
import java.util.Map;

/**
 * Builds a cryptographic information for the ETSI Validation report
 */
public class CryptographicInformationBuilder {

	/** The conclusion */
	private final XmlConclusion conclusion;

	/** The constraint */
	private final CryptographicConstraint constraint;

	/** Digest Algorithm */
	private final DigestAlgorithm digestAlgorithm;

	/** Encryption Algorithm */
	private final EncryptionAlgorithm encryptionAlgorithm;

	/** Mask generation function */
	private final MaskGenerationFunction maskGenerationFunction;

	/** Key length used to sign the token */
	private final String keyLength;

	/** Object description */
	private final String objectDescription;

	/**
	 * Default constructor to validate {@code TokenProxy}
	 *
	 * @param token {@link TokenProxy}
	 * @param conclusion {@link XmlConclusion}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public CryptographicInformationBuilder(TokenProxy token, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this(token.getDigestAlgorithm(), token.getEncryptionAlgorithm(), token.getMaskGenerationFunction(), token.getKeyLengthUsedToSignThisToken(), 
				token.getId(), conclusion, constraint);
	}

	/**
	 * Default constructor to validate {@code XmlDigestMatcher}
	 *
	 * @param digestMatcher {@link TokenProxy}
	 * @param conclusion {@link XmlConclusion}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public CryptographicInformationBuilder(XmlDigestMatcher digestMatcher, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this(digestMatcher.getDigestMethod(), null, null, null, getDigestMatcherDescription(digestMatcher), conclusion, constraint);
	}
	
	private static String getDigestMatcherDescription(XmlDigestMatcher digestMatcher) {
		StringBuilder description = new StringBuilder(digestMatcher.getType().name());
		if (Utils.isStringNotEmpty(digestMatcher.getName())) {
			description.append(" with name [").append(digestMatcher.getName()).append("]");
		}
		return description.toString();
	}
	
	private CryptographicInformationBuilder(DigestAlgorithm digestAlgorithm, EncryptionAlgorithm encryptionAlgorithm, MaskGenerationFunction maskGenerationFunction,
			String keyLength, String objectDecription, XmlConclusion conclusion, CryptographicConstraint constraint) {
		this.digestAlgorithm = digestAlgorithm;
		this.encryptionAlgorithm = encryptionAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
		this.keyLength = keyLength;
		this.objectDescription =objectDecription;
		
		this.conclusion = conclusion;
		this.constraint = constraint;
	}
	
	public XmlCryptographicInformation build() {
		XmlCryptographicInformation cryptoInfo = new XmlCryptographicInformation();
		cryptoInfo.setAlgorithm(getAlgorithmURI());
		cryptoInfo.setKeyLength(keyLength);
		cryptoInfo.setSecure(isSecure(conclusion));
		cryptoInfo.setNotAfter(getNotAfter());
		cryptoInfo.setConcernedMaterial(objectDescription);
		return cryptoInfo;
	}

	private String getAlgorithmURI() {
		try {
			if (encryptionAlgorithm != null) {
				return getSignatureAlgorithmUri(digestAlgorithm, encryptionAlgorithm, maskGenerationFunction);
			} else {
				return getDigestAlgorithmUri(digestAlgorithm);
			}
		} catch (Exception e) {
			return "???";
		}
	}
	
	private String getSignatureAlgorithmUri(DigestAlgorithm digestAlgorithm, 
			EncryptionAlgorithm encryptionAlgorithm, MaskGenerationFunction maskGenerationFunction) {
		SignatureAlgorithm sigAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, maskGenerationFunction);
		return sigAlgo.getUri() != null ? sigAlgo.getUri() : sigAlgo.getURIBasedOnOID();
	}
	
	private String getDigestAlgorithmUri(DigestAlgorithm digestAlgorithm) {
		return digestAlgorithm.getUri() != null ? digestAlgorithm.getUri() : digestAlgorithm.getOid();
	}
	
	private boolean isSecure(XmlConclusion conclusion) {
		return Indication.PASSED.equals(conclusion.getIndication());
	}
	
	private Date getNotAfter() {
		if (constraint != null) {
			Date notAfter = null;
			CryptographicConstraintWrapper wrapper = new CryptographicConstraintWrapper(constraint);
			Map<String, Date> expirationDates = wrapper.getExpirationTimes();
			String digestAlgoToFind = digestAlgorithm == null ? Utils.EMPTY_STRING : digestAlgorithm.getName();
			notAfter = expirationDates.get(digestAlgoToFind);
			String encryptionAlgoToFind = encryptionAlgorithm == null ? Utils.EMPTY_STRING : encryptionAlgorithm.name();
			int keySize = Utils.isStringDigits(keyLength) ? Integer.parseInt(keyLength) : 0;
			Date expirationEncryption = wrapper.getExpirationDate(encryptionAlgoToFind, keySize);
			if (notAfter != null && encryptionAlgorithm != null && (expirationEncryption == null || expirationEncryption.before(notAfter))) {
				notAfter = expirationEncryption;
			}
			return notAfter;
		}
		return null;
	}

}
