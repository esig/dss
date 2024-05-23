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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSPDocSpecification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.diagnostic.jaxb.XmlUserNotice;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.model.signature.SignaturePolicyValidationResult;

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

	/** The found SignaturePolicyStore from a signature */
	private SignaturePolicyStore signaturePolicyStore;
	
	/**
	 * The default constructor
	 * 
	 * @param signaturePolicy {@link SignaturePolicy} to build {@code XmlPolicy} from
	 */
	public XmlPolicyBuilder(final SignaturePolicy signaturePolicy) {
		Objects.requireNonNull(signaturePolicy, "SignaturePolicy cannot be null!");
		this.signaturePolicy = signaturePolicy;
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
		xmlPolicy.setDescription(signaturePolicy.getDescription());
		xmlPolicy.setDocumentationReferences(signaturePolicy.getDocumentationReferences());

		xmlPolicy.setUrl(DSSUtils.removeControlCharacters(signaturePolicy.getUri()));
		final UserNotice userNotice = signaturePolicy.getUserNotice();
		if (userNotice != null) {
			XmlUserNotice xmlUserNotice = new XmlUserNotice();
			xmlUserNotice.setOrganization(userNotice.getOrganization());
			if (userNotice.getNoticeNumbers() != null && userNotice.getNoticeNumbers().length > 0) {
				xmlUserNotice.getNoticeNumbers().addAll(DSSUtils.toBigIntegerList(userNotice.getNoticeNumbers()));
			}
			xmlUserNotice.setExplicitText(userNotice.getExplicitText());
			xmlPolicy.setUserNotice(xmlUserNotice);
		}
		final SpDocSpecification spDocSpecification = signaturePolicy.getDocSpecification();
		if (spDocSpecification != null) {
			XmlSPDocSpecification xmlSPDocSpecification = new XmlSPDocSpecification();
			xmlSPDocSpecification.setId(spDocSpecification.getId());
			xmlSPDocSpecification.setDescription(spDocSpecification.getDescription());
			String[] documentationReferences = spDocSpecification.getDocumentationReferences();
			if (Utils.isArrayNotEmpty(documentationReferences)) {
				xmlSPDocSpecification.setDocumentationReferences(Arrays.asList(documentationReferences));
			}
			xmlPolicy.setDocSpecification(xmlSPDocSpecification);
		}
		
		List<String> transformsDescription = signaturePolicy.getTransformsDescription();
		if (Utils.isCollectionNotEmpty(transformsDescription)) {
			xmlPolicy.setTransformations(transformsDescription);
		}

		final SignaturePolicyValidationResult validationResult = signaturePolicy.getValidationResult();

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
			final SignaturePolicyValidationResult validationResult = signaturePolicy.getValidationResult();
			Digest recalculatedDigest = validationResult.getDigest();
			if (recalculatedDigest != null) {
				xmlSignaturePolicyStore.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(recalculatedDigest));
			}
		}
		xmlSignaturePolicyStore.setSigPolDocLocalURI(signaturePolicyStore.getSigPolDocLocalURI());

		return xmlSignaturePolicyStore;
	}

	private XmlDigestAlgoAndValue getXmlDigestAlgoAndValue(Digest digest) {
		XmlDigestAlgoAndValue xmlDigestAlgAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgAndValue.setDigestMethod(digest.getAlgorithm());
		xmlDigestAlgAndValue.setDigestValue(digest.getValue() == null ? DSSUtils.EMPTY_BYTE_ARRAY : digest.getValue());
		return xmlDigestAlgAndValue;
	}

}
