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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidationResult;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * The class is used to validate a {@code SignaturePolicy} and build a {@code XmlPolicy}
 *
 */
public class XmlPolicyBuilder {

	/** The {@code SignaturePolicy} to incorporate into the DiagnosticData */
	private final SignaturePolicy signaturePolicy;

	/** The result of a signature policy validation */
	private final SignaturePolicyValidationResult validationResult;

	/** The found SignaturePolicyStore from a signature */
	private SignaturePolicyStore signaturePolicyStore;
	
	/**
	 * The default constructor
	 * 
	 * @param signaturePolicy {@link SignaturePolicy} to build {@code XmlPolicy} from
	 * @param validationResult {@link SignaturePolicyValidationResult} the output of signature policy validation
	 */
	public XmlPolicyBuilder(final SignaturePolicy signaturePolicy, final SignaturePolicyValidationResult validationResult) {
		Objects.requireNonNull(signaturePolicy, "SignaturePolicy cannot be null!");
		Objects.requireNonNull(validationResult, "The result of a signature policy validation cannot be null!");
		this.signaturePolicy = signaturePolicy;
		this.validationResult = validationResult;
	}

	/**
	 * Sets {@code SignaturePolicyStore} extracted from a signature when applicable
	 * 
	 * @param signaturePolicyStore {@link SignaturePolicyStore}
	 * @return {@link XmlPolicyBuilder} this
	 */
	public XmlPolicyBuilder setSignaturePolicyStore(SignaturePolicyStore signaturePolicyStore) {
		this.signaturePolicyStore = signaturePolicyStore;
		return this;
	}
	
	/**
	 * Validates a {@code SignaturePolicy} and builds an {@code XmlPolicy}
	 * 
	 * @return {@link XmlPolicy}
	 */
	public XmlPolicy build() {
		final XmlPolicy xmlPolicy = new XmlPolicy();

		xmlPolicy.setId(signaturePolicy.getIdentifier());
		xmlPolicy.setUrl(DSSUtils.removeControlCharacters(signaturePolicy.getUrl()));
		xmlPolicy.setNotice(signaturePolicy.getNotice());
		xmlPolicy.setDocSpecification(signaturePolicy.getDocSpecification());
		xmlPolicy.setDescription(signaturePolicy.getDescription());
		xmlPolicy.setDocumentationReferences(signaturePolicy.getDocumentationReferences());
		
		List<String> transformsDescription = signaturePolicy.getTransformsDescription();
		if (Utils.isCollectionNotEmpty(transformsDescription)) {
			xmlPolicy.setTransformations(transformsDescription);
		}

		XmlPolicyDigestAlgoAndValue xmlPolicyDigestAlgoAndValue = new XmlPolicyDigestAlgoAndValue();
		if (signaturePolicy.isZeroHash()) {
			xmlPolicyDigestAlgoAndValue.setZeroHash(signaturePolicy.isZeroHash());
		} else {
			xmlPolicyDigestAlgoAndValue.setDigestAlgorithmsEqual(validationResult.isDigestAlgorithmsEqual());
		}
		final Digest digest = signaturePolicy.getDigest();
		if (digest != null) {
			XmlDigestAlgoAndValue xmlDigestAlgoAndValue = getXmlDigestAlgoAndValue(digest);
			xmlPolicyDigestAlgoAndValue.setDigestMethod(xmlDigestAlgoAndValue.getDigestMethod());
			xmlPolicyDigestAlgoAndValue.setDigestValue(xmlDigestAlgoAndValue.getDigestValue());
		}
		xmlPolicyDigestAlgoAndValue.setMatch(validationResult.isDigestValid());
		xmlPolicy.setDigestAlgoAndValue(xmlPolicyDigestAlgoAndValue);

		xmlPolicy.setAsn1Processable(validationResult.isAsn1Processable());
		xmlPolicy.setIdentified(validationResult.isIdentified());
		if (Utils.isStringNotBlank(validationResult.getProcessingErrors())) {
			xmlPolicy.setProcessingError(validationResult.getProcessingErrors());
		}
		
		return xmlPolicy;
	}
	
	/**
	 * Builds an {@code XmlSignaturePolicyStore}
	 * 
	 * @return {@link XmlSignaturePolicyStore}
	 */
	public XmlSignaturePolicyStore buildSignaturePolicyStore() {
		if (signaturePolicyStore == null) {
			return null;
		}

		XmlSignaturePolicyStore xmlSignaturePolicyStore = new XmlSignaturePolicyStore();
		SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
		if (spDocSpecification != null) {
			xmlSignaturePolicyStore.setId(spDocSpecification.getId());
			xmlSignaturePolicyStore.setDescription(spDocSpecification.getDescription());
			String[] documentationReferences = spDocSpecification.getDocumentationReferences();
			if (Utils.isArrayNotEmpty(documentationReferences)) {
				xmlSignaturePolicyStore.setDocumentationReferences(Arrays.asList(documentationReferences));
			}
		}
		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent != null) {
			Digest recalculatedDigest = validationResult.getDigest();
			xmlSignaturePolicyStore.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(recalculatedDigest));
		}
		return xmlSignaturePolicyStore;
	}

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(Digest digest) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digest.getAlgorithm());
		xmlDigestAlgAndValue.setDigestValue(digest.getValue() == null ? DSSUtils.EMPTY_BYTE_ARRAY : digest.getValue());
		return xmlDigestAlgAndValue;
	}

}
