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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds a SignaturePolicyStore for a CAdES signature
 */
public class CAdESSignaturePolicyStoreBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignaturePolicyStoreBuilder.class);

	/**
	 * Extends all signatures within the given document, matching the provided policy in {@code SignaturePolicyStore}
	 *
	 * @param signatureDocument {@link DSSDocument} to extend
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link CMSSignedData} with a SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument signatureDocument, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signatureDocument, "Signature document must be provided!");

		CMSSignedData originalCmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		CMSSignedData newCmsSignedData = extendCMSSignedData(originalCmsSignedData, signaturePolicyStore);
		newCmsSignedData = CMSUtils.populateDigestAlgorithmSet(newCmsSignedData, originalCmsSignedData);
		return new CMSSignedDocument(newCmsSignedData);
	}

	/**
	 * Creates a new CMSSignedData with a SignaturePolicyStore for matching signatures
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link CMSSignedData} with a SignaturePolicyStore
	 */
	public CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(cmsSignedData, "CMSSignedData must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		CMSDocumentValidator documentValidator = new CMSDocumentValidator(cmsSignedData);
		List<AdvancedSignature> signatures = documentValidator.getSignatures();

		if (Utils.isCollectionEmpty(signatures)) {
			throw new IllegalInputException("Unable to extend the document! No signatures found.");
		}

		final List<SignerInformation> newSignerInformationList = new ArrayList<>();

		boolean signaturePolicyStoreAdded = false;
		for (AdvancedSignature signature : signatures) {
			CAdESSignature cadesSignature = (CAdESSignature) signature;
			SignerInformation newSignerInformation = addSignaturePolicyStoreIfDigestMatch(cadesSignature, signaturePolicyStore);
			if (cadesSignature.getSignerInformation() != newSignerInformation) {
				signaturePolicyStoreAdded = true;
			}
			newSignerInformationList.add(newSignerInformation);
		}
		if (!signaturePolicyStoreAdded) {
			throw new IllegalInputException("The process did not find a signature to add SignaturePolicyStore!");
		}
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		return CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
	}

	/**
	 * Adds a signaturePolicyStore to a signature with the given {@code signatureId},
	 * if the signature policy identifier matches the policy provided within {@code SignaturePolicyStore}
	 *
	 * @param signatureDocument {@link DSSDocument} containing signatures to add signature policy store into
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @param signatureId {@link String} Id of a signature to add SignaturePolicyStore for
	 * @return {@link DSSDocument} with signaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument signatureDocument, SignaturePolicyStore signaturePolicyStore,
											   String signatureId) {
		Objects.requireNonNull(signatureDocument, "Signature document must be provided!");

		CMSSignedData originalCmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		CMSSignedData newCmsSignedData = extendCMSSignedData(originalCmsSignedData, signaturePolicyStore, signatureId);
		newCmsSignedData = CMSUtils.populateDigestAlgorithmSet(newCmsSignedData, originalCmsSignedData);
		return new CMSSignedDocument(newCmsSignedData);
	}

	/**
	 * Creates a new CMSSignedData with a SignaturePolicyStore for a signature with {@code signatureId}
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @param signatureId {@link String} id of a signature to add signature policy store to
	 * @return {@link CMSSignedData} with a SignaturePolicyStore
	 */
	public CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, SignaturePolicyStore signaturePolicyStore,
											 String signatureId) {
		Objects.requireNonNull(cmsSignedData, "CMSSignedData must be provided!");
		assertConfigurationValid(signaturePolicyStore);

		CMSDocumentValidator documentValidator = new CMSDocumentValidator(cmsSignedData);
		AdvancedSignature signature = documentValidator.getSignatureById(signatureId);
		if (signature == null) {
			throw new IllegalInputException(String.format("Unable to find a signature with Id : %s!", signatureId));
		}

		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		for (AdvancedSignature currentSignature : documentValidator.getSignatures()) {
			CAdESSignature cadesSignature = (CAdESSignature) currentSignature;
			if (signature.equals(cadesSignature)) {
				SignerInformation newSignerInformation = addSignaturePolicyStoreIfDigestMatch(cadesSignature, signaturePolicyStore);
				if (cadesSignature.getSignerInformation() == newSignerInformation) {
					throw new IllegalInputException(String.format(
							"The process was not able to add SignaturePolicyStore to a signature with Id : %s!", signatureId));
				}
				newSignerInformationList.add(newSignerInformation);

			} else {
				newSignerInformationList.add(cadesSignature.getSignerInformation());
			}
		}
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		return CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
	}

	/**
	 * This method adds {@code SignaturePolicyStore} to a {@code cadesSignature} if required
	 *
	 * @param cadesSignature {@link CAdESSignature} signature to add {@link SignaturePolicyStore}
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be added
	 * @return {@link SignerInformation} containing {@link SignaturePolicyStore} if it has been added,
	 * 			original {@link SignerInformation} otherwise
	 */
	protected SignerInformation addSignaturePolicyStoreIfDigestMatch(CAdESSignature cadesSignature,
														   SignaturePolicyStore signaturePolicyStore) {
		SignerInformation signerInformation = cadesSignature.getSignerInformation();

		assertSignaturePolicyStoreExtensionPossible(signerInformation);
		SignerInformation newSignerInformation = signerInformation;

		if (checkDigest(cadesSignature, signaturePolicyStore)) {
			newSignerInformation = addSignaturePolicyStore(signerInformation, signaturePolicyStore);
		}
		return newSignerInformation;
	}

	/**
	 * This method verifies if the digests computed in the provided {@code SignaturePolicyStore} match
	 * the digest defined in the incorporated signature policy identifier
	 *
	 * @param cadesSignature {@link CAdESSignature} to check signature policy identifier
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to be incorporated
	 * @return TRUE if the digest match and {@link SignaturePolicyStore} can be embedded, FALSE otherwise
	 */
	protected boolean checkDigest(CAdESSignature cadesSignature, SignaturePolicyStore signaturePolicyStore) {
		final SignaturePolicy signaturePolicy = cadesSignature.getSignaturePolicy();
		if (signaturePolicy == null) {
			LOG.warn("signature-policy-identifier is not defined for a signature with Id : {}", cadesSignature.getId());
			return false;
		}
		final Digest expectedDigest = signaturePolicy.getDigest();
		if (expectedDigest == null) {
			LOG.warn("signature-policy-identifier digest is not found for a signature with Id : {}", cadesSignature.getId());
			return false;
		}

		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent == null) {
			LOG.info("No policy document has been provided. Digests are not checked!");
			return true;
		}
		signaturePolicy.setPolicyContent(signaturePolicyContent);

		SignaturePolicyValidator validator = new DefaultSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
		Digest computedDigest = validator.getComputedDigest(signaturePolicyContent, expectedDigest.getAlgorithm());

		boolean digestMatch = expectedDigest.equals(computedDigest);
		if (!digestMatch) {
			LOG.warn("Signature policy's digest {} doesn't match the digest extracted from document {} for signature with Id : {}",
					computedDigest, expectedDigest, cadesSignature.getId());
		}
		return digestMatch;
	}
	
	private SignerInformation addSignaturePolicyStore(SignerInformation signerInformation, SignaturePolicyStore signaturePolicyStore) {
		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		ASN1Sequence sigPolicyStore = getSignaturePolicyStore(signaturePolicyStore);
		AttributeTable unsignedAttributesWithPolicyStore = unsignedAttributes.add(OID.id_aa_ets_sigPolicyStore, sigPolicyStore);
		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributesWithPolicyStore);
	}

	/**
	 * SignaturePolicyStore ::= SEQUENCE {
	 *  spDocSpec SPDocSpecification ,
	 *  spDocument SignaturePolicyDocument
	 * }
	 * SignaturePolicyDocument ::= CHOICE {
	 *  sigPolicyEncoded OCTET STRING,
	 *  sigPolicyLocalURI IA5String
	 * }
	 */
	private ASN1Sequence getSignaturePolicyStore(SignaturePolicyStore signaturePolicyStore) {
		final ASN1EncodableVector sigPolicyStore = new ASN1EncodableVector();
		// spDocSpec
		sigPolicyStore.add(DSSASN1Utils.buildSPDocSpecificationId(signaturePolicyStore.getSpDocSpecification().getId()));
		// spDocument
		DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
		if (signaturePolicyContent != null) {
			sigPolicyStore.add(new DEROctetString(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));
		}
		String sigPolDocLocalURI = signaturePolicyStore.getSigPolDocLocalURI();
		if (sigPolDocLocalURI != null) {
			sigPolicyStore.add(new DERIA5String(sigPolDocLocalURI));
		}
		return new DERSequence(sigPolicyStore);
	}

	private void assertConfigurationValid(SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");

		boolean signaturePolicyContentPresent = signaturePolicyStore.getSignaturePolicyContent() != null;
		boolean sigPolDocLocalURIPresent = signaturePolicyStore.getSigPolDocLocalURI() != null;
		if (!(signaturePolicyContentPresent ^ sigPolDocLocalURIPresent)) {
			throw new IllegalArgumentException("SignaturePolicyStore shall contain either " +
					"SignaturePolicyContent document or sigPolDocLocalURI!");
		}
	}
	
	private void assertSignaturePolicyStoreExtensionPossible(SignerInformation signerInformation) {
		if (CMSUtils.containsATSTv2(signerInformation)) {
			throw new IllegalInputException("Cannot add signature policy store to a CAdES containing an archiveTimestampV2");
		}
	}

}
