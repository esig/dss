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
package eu.europa.esig.dss.validation.process.bbb.aov.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.validation.policy.CryptographicSuiteUtils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.checks.PublicKeySizeAcceptableCheck;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.checks.PublicKeySizeKnownCheck;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.checks.SignatureAlgorithmAtValidationTimeCheck;
import eu.europa.esig.dss.validation.process.bbb.aov.cc.checks.SignatureAlgorithmReliableCheck;

import java.util.Date;

/**
 * Runs the cryptographic validation for a SignatureAlgorithm with a given key length
 *
 */
public class SignatureAlgorithmCryptographicChecker extends AbstractAlgorithmCryptographicChecker {

	/** The Signature algorithm */
	private final SignatureAlgorithm signatureAlgorithm;

	/** Used Key length */
	private final String keyLengthUsedToSignThisToken;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param signatureAlgorithm {@link SignatureAlgorithm} to validate
	 * @param keyLengthUsedToSignThisToken {@link String}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param cryptographicSuite {@link CryptographicSuite}
	 */
	public SignatureAlgorithmCryptographicChecker(I18nProvider i18nProvider, SignatureAlgorithm signatureAlgorithm, String keyLengthUsedToSignThisToken,
												  Date validationDate, MessageTag position, CryptographicSuite cryptographicSuite) {
		super(i18nProvider, validationDate, position, cryptographicSuite);

		this.signatureAlgorithm = signatureAlgorithm;
		this.keyLengthUsedToSignThisToken = keyLengthUsedToSignThisToken;
	}

	@Override
	protected void initChain() {
		
		ChainItem<XmlCC> item = firstItem = signatureAlgorithmReliable();
		
		item = item.setNextItem(publicKeySizeKnown());
		
		item = item.setNextItem(publicKeySizeAcceptable());

		item = item.setNextItem(signatureAlgorithmOnValidationTime());
		
	}

	/**
	 * Checks if the {@code signatureAlgorithm} is acceptable
	 *
	 * @return TRUE if the {@code signatureAlgorithm} is acceptable, FALSE otherwise
	 */
	protected ChainItem<XmlCC> signatureAlgorithmReliable() {
		return new SignatureAlgorithmReliableCheck(i18nProvider, signatureAlgorithm, result, position, cryptographicSuite);
	}

	/**
	 * Checks if the {@code keyLengthUsedToSignThisToken} is known
	 *
	 * @return TRUE if the {@code keyLengthUsedToSignThisToken} is known, FALSE otherwise
	 */
	protected ChainItem<XmlCC> publicKeySizeKnown() {
		return new PublicKeySizeKnownCheck(i18nProvider, keyLengthUsedToSignThisToken, result, position, cryptographicSuite);
	}

	/**
	 * Checks if the {@code keyLengthUsedToSignThisToken} is acceptable
	 *
	 * @return TRUE if the {@code keyLengthUsedToSignThisToken} is acceptable, FALSE otherwise
	 */
	protected ChainItem<XmlCC> publicKeySizeAcceptable() {
		return new PublicKeySizeAcceptableCheck(i18nProvider, signatureAlgorithm, keyLengthUsedToSignThisToken, result, position, cryptographicSuite);
	}

	/**
	 * Checks if the {@code signatureAlgorithm} is not expired in validation time
	 *
	 * @return TRUE if the {@code signatureAlgorithm} is not expired in validation time, FALSE otherwise
	 */
	protected ChainItem<XmlCC> signatureAlgorithmOnValidationTime() {
		return new SignatureAlgorithmAtValidationTimeCheck(i18nProvider, signatureAlgorithm, keyLengthUsedToSignThisToken, validationDate, result,
				position, cryptographicSuite);
	}

	@Override
	protected XmlCryptographicAlgorithm getAlgorithm() {
		if (cryptographicAlgorithm == null) {
			cryptographicAlgorithm = new XmlCryptographicAlgorithm();
			if (signatureAlgorithm != null) {
				// if SignatureAlgorithm is defined
				cryptographicAlgorithm.setName(ValidationProcessUtils.getSignatureAlgorithmName(signatureAlgorithm, i18nProvider));
				cryptographicAlgorithm.setUri(getSignatureAlgorithmUri(signatureAlgorithm));
				cryptographicAlgorithm.setKeyLength(keyLengthUsedToSignThisToken);

			} else {
				// if SignatureAlgorithm is not found
				cryptographicAlgorithm.setName(ALGORITHM_UNIDENTIFIED);
				cryptographicAlgorithm.setUri(ALGORITHM_UNIDENTIFIED_URN);
			}
		}
		return cryptographicAlgorithm;
	}

	private String getSignatureAlgorithmUri(SignatureAlgorithm signatureAlgorithm) {
		if (signatureAlgorithm != null) {
			if (signatureAlgorithm.getUri() != null) {
				return signatureAlgorithm.getUri();
			}
			if (signatureAlgorithm.getOid() != null) {
				return signatureAlgorithm.getURIBasedOnOID();
			}
		}
		return ALGORITHM_UNIDENTIFIED_URN;
	}

	@Override
	protected Date getNotAfter() {
		if (CryptographicSuiteUtils.isSignatureAlgorithmReliable(cryptographicSuite, signatureAlgorithm) &&
				CryptographicSuiteUtils.isSignatureAlgorithmWithKeySizeReliable(cryptographicSuite, signatureAlgorithm, keyLengthUsedToSignThisToken)) {
			return CryptographicSuiteUtils.getExpirationDate(cryptographicSuite, signatureAlgorithm, keyLengthUsedToSignThisToken);
		}
		return null;
	}

}
