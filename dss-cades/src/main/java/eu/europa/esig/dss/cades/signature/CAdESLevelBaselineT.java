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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;

import java.util.ArrayList;
import java.util.List;

import static eu.europa.esig.dss.enumerations.SignatureLevel.CAdES_BASELINE_T;

/**
 * This class holds the CAdES-T signature profile; it supports the inclusion of the mandatory unsigned
 * id-aa-signatureTimeStampToken attribute as specified in ETSI TS 101 733 V1.8.1, clause 6.1.1.
 *
 */
public class CAdESLevelBaselineT extends CAdESSignatureExtension {

	/**
	 * The default constructor with a {@code CertificateVerifier}
	 *
	 * @param tspSource {@link TSPSource} to request a timestamp
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESLevelBaselineT(TSPSource tspSource, CertificateVerifier certificateVerifier) {
		super(tspSource, certificateVerifier);
	}

	@Override
	protected CMS extendCMSSignatures(CMS cms, CAdESSignatureParameters parameters,
									  List<String> signatureIdsToExtend) {
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();

		CMSDocumentAnalyzer documentAnalyzer = getDocumentValidator(cms, parameters);
		List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();
		if (Utils.isCollectionEmpty(signatures)) {
			throw new IllegalInputException("There is no signature to extend!");
		}

		final List<AdvancedSignature> signaturesToExtend = getExtendToTLevelSignatures(signatures, signatureIdsToExtend, parameters);
		if (Utils.isCollectionEmpty(signaturesToExtend)) {
			return cms;
		}

		final SignatureRequirementsChecker signatureRequirementsChecker = getSignatureRequirementsChecker(parameters);
		signatureRequirementsChecker.assertExtendToTLevelPossible(signaturesToExtend);

		signatureRequirementsChecker.assertSignaturesValid(signaturesToExtend);
		signatureRequirementsChecker.assertSigningCertificateIsValid(signaturesToExtend);

		for (AdvancedSignature signature : signatures) {
			final CAdESSignature cadesSignature = (CAdESSignature) signature;
			final SignerInformation signerInformation = cadesSignature.getSignerInformation();
			SignerInformation newSignerInformation = signerInformation;
			if (signaturesToExtend.contains(cadesSignature)) {
				newSignerInformation = extendSignerInformation(signerInformation, parameters);
			}
			newSignerInformationList.add(newSignerInformation);
		}

		return replaceSigners(cms, newSignerInformationList);
	}

	private SignerInformation extendSignerInformation(SignerInformation signerInformation,
													  CAdESSignatureParameters parameters) {
		AttributeTable unsignedAttributes = CAdESUtils.getUnsignedAttributes(signerInformation);
		unsignedAttributes = addSignatureTimestampAttribute(signerInformation, unsignedAttributes, parameters);
		return CMSUtils.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}

	/**
	 * Instantiates a {@code SignatureRequirementsChecker}
	 *
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link SignatureRequirementsChecker}
	 */
	protected SignatureRequirementsChecker getSignatureRequirementsChecker(CAdESSignatureParameters parameters) {
		return new SignatureRequirementsChecker(certificateVerifier, parameters);
	}

	private List<AdvancedSignature> getExtendToTLevelSignatures(List<AdvancedSignature> signatures, List<String> signatureIdsToExtend,
																CAdESSignatureParameters parameters) {
		final List<AdvancedSignature> toBeExtended = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			if (signatureIdsToExtend.contains(signature.getId()) && tLevelExtensionRequired(signature, parameters)) {
				toBeExtended.add(signature);
			}
		}
		return toBeExtended;
	}

	private boolean tLevelExtensionRequired(AdvancedSignature cadesSignature, CAdESSignatureParameters parameters) {
		return CAdES_BASELINE_T.equals(parameters.getSignatureLevel()) || !cadesSignature.hasTProfile();
	}

	private AttributeTable addSignatureTimestampAttribute(SignerInformation signerInformation, AttributeTable unsignedAttributes,
			CAdESSignatureParameters parameters) {
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		final DSSMessageDigest messageDigest = new DSSMessageDigest(
				timestampDigestAlgorithm, DSSUtils.digest(timestampDigestAlgorithm, signerInformation.getSignature()));
		ASN1Object signatureTimeStamp = getTimeStampAttributeValue(messageDigest, timestampDigestAlgorithm);
		return unsignedAttributes.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, signatureTimeStamp);
	}

}
