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
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.ArrayList;
import java.util.List;

/**
 * Creates Signature parameters for a Trusted List creation
 * 
 * NOTE: the same instance of SignatureParameters shall be used on calls
 * {@code DocumentSignatureService.getDataToSign(...)} and {@code DocumentSignatureService.signDocument(...)}
 *
 */
public class TrustedListSignatureParametersBuilder extends AbstractSignatureParametersBuilder<XAdESSignatureParameters> {
	
	/**
	 * The EXCLUSIVE canonicalization shall be used
	 * See TS 119 612 "B.1 The Signature element"
	 */
	private static final String DEFAULT_CANONICALIZATION = CanonicalizationMethod.EXCLUSIVE;

	/** The default prefix for an enveloped signature reference id */
	private static final String DEFAULT_REFERENCE_PREFIX = "ref-enveloped-signature";
	
	/**
	 * The XML Trusted List document
	 */
	private final DSSDocument tlXmlDocument;
	
	/**
	 * The Enveloped reference Id to use
	 */
	private String referenceId;
	
	/**
	 * The DigestAlgorithm to be used for an Enveloped reference
	 */
	private DigestAlgorithm referenceDigestAlgorithm = DigestAlgorithm.SHA256;
	
	/**
	 * The constructor to build Signature Parameters for a Trusted List signing with respect to ETSI TS 119 612
	 * 
	 * @param signingCertificate {@link CertificateToken} to be used for a signature creation
	 * @param tlXmlDocument {@link DSSDocument} Trusted List XML document to be signed
	 */
	public TrustedListSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument tlXmlDocument) {
		super(signingCertificate);
		this.tlXmlDocument = tlXmlDocument;
	}

	/**
	 * Sets an Enveloped Reference Id to use
	 *
	 * Default: "ref-enveloped-signature"
	 * 
	 * @param referenceId {@link String} reference Id
	 * @return this builder
	 */
	public TrustedListSignatureParametersBuilder setReferenceId(String referenceId) {
		this.referenceId = referenceId;
		return this;
	}

	/**
	 * Sets an Enveloped Reference {@code DigestAlgorithm} to use
	 * 
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used
	 * @return this builder
	 */
	public TrustedListSignatureParametersBuilder setReferenceDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.referenceDigestAlgorithm = digestAlgorithm;
		return this;
	}

	@Override
	public TrustedListSignatureParametersBuilder setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (TrustedListSignatureParametersBuilder) super.setDigestAlgorithm(digestAlgorithm);
	}

	@Override
	public TrustedListSignatureParametersBuilder setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		return (TrustedListSignatureParametersBuilder) super.setEncryptionAlgorithm(encryptionAlgorithm);
	}

	@Override
	public TrustedListSignatureParametersBuilder setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
		return (TrustedListSignatureParametersBuilder) super.setMaskGenerationFunction(maskGenerationFunction);
	}

	@Override
	public TrustedListSignatureParametersBuilder setBLevelParams(BLevelParameters bLevelParams) {
		return (TrustedListSignatureParametersBuilder) super.setBLevelParams(bLevelParams);
	}

	@Override
	protected XAdESSignatureParameters initParameters() {
		return new XAdESSignatureParameters();
	}
	
	@Override
	public XAdESSignatureParameters build() {
		final XAdESSignatureParameters signatureParameters = super.build();

		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setEn319132(false);
		
		final List<DSSReference> references = new ArrayList<>();

		DSSReference dssReference = new DSSReference();
		if (referenceId != null) {
			dssReference.setId(referenceId);
		} else {
			dssReference.setId(DEFAULT_REFERENCE_PREFIX);
		}
		dssReference.setUri("");
		dssReference.setContents(tlXmlDocument);
		dssReference.setDigestMethodAlgorithm(referenceDigestAlgorithm);

		final List<DSSTransform> transforms = new ArrayList<>();

		EnvelopedSignatureTransform signatureTransform = new EnvelopedSignatureTransform();
		transforms.add(signatureTransform);

		CanonicalizationTransform dssTransform = new CanonicalizationTransform(DEFAULT_CANONICALIZATION);
		transforms.add(dssTransform);

		dssReference.setTransforms(transforms);
		references.add(dssReference);

		signatureParameters.setReferences(references);
		
		return signatureParameters;
	}

}
