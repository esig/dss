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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Checks if message-digest (CAdES/PAdES) or SignedProperties (XAdES) is present
 */
public class MessageDigestOrSignedPropertiesCheck extends ChainItem<XmlSAV> {

	/** The signature to check */
	private final SignatureWrapper signature;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlSAV}
	 * @param signature {@link SignatureWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public MessageDigestOrSignedPropertiesCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
												LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		switch (signature.getSignatureFormat().getSignatureForm()) {
			case XAdES:
				return isRequiredDigestMatcherPresent(DigestMatcherType.SIGNED_PROPERTIES);
			case CAdES:
			case PAdES:
			case PKCS7:
				return isRequiredDigestMatcherPresent(DigestMatcherType.MESSAGE_DIGEST);
			default:
				// JAdES shall be skipped
				return false;
		}
	}
	
	private boolean isRequiredDigestMatcherPresent(DigestMatcherType digestMatcherType) {
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		if (Utils.isCollectionNotEmpty(digestMatchers)) {
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				if (digestMatcherType.equals(digestMatcher.getType())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPMDOSPP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPMDOSPP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
