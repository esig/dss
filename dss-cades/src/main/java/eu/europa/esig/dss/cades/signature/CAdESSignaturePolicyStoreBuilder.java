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
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Builds a SignaturePolicyStore for a CAdES signature
 */
public class CAdESSignaturePolicyStoreBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignaturePolicyStoreBuilder.class);

	/**
	 * Creates a new CMSSignedData with a SignaturePolicyStore
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link CMSSignedData} with a SignaturePolicyStore
	 */
	public CMSSignedData addSignaturePolicyStore(CMSSignedData cmsSignedData, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(cmsSignedData, "CMSSignedData must be provided");
		Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");
		Objects.requireNonNull(signaturePolicyStore.getSignaturePolicyContent(), "Signature policy content must be provided");
		
		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		if (Utils.isCollectionEmpty(signerInformationCollection)) {
			throw new IllegalInputException("Unable to extend the document! No signatures found.");
		}
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		
		for (SignerInformation signerInformation : signerInformationCollection) {
			assertSignaturePolicyStoreExtensionPossible(signerInformation);
			SignerInformation newSignerInformation = signerInformation;
			
			CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
			SignaturePolicy signaturePolicy = cadesSignature.getSignaturePolicy();
			if (signaturePolicy != null) {
				signaturePolicy.setPolicyContent(signaturePolicyStore.getSignaturePolicyContent());
				Digest expectedDigest = signaturePolicy.getDigest();
				if (expectedDigest != null) {
					SignaturePolicyValidator validator = new DefaultSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
					Digest computedDigest = validator.getComputedDigest(signaturePolicyStore.getSignaturePolicyContent(), expectedDigest.getAlgorithm());
					if (expectedDigest.equals(computedDigest)) {
						newSignerInformation = addSignaturePolicyStore(signerInformation, signaturePolicyStore);
					} else {
						LOG.warn("Signature policy's digest doesn't match the document {} for signature {}", expectedDigest, cadesSignature.getId());
					}
				} else {
					LOG.warn("SignaturePolicyIdentifier Digest is not found for a signature with id {}", cadesSignature.getId());
				}
			} else {
				LOG.warn("SignaturePolicyIdentifier is not defined for a signature with id {}", cadesSignature.getId());
			}
			newSignerInformationList.add(newSignerInformation);
		}
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		
		return CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
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
		// spDocument : only complete octets supported
		sigPolicyStore.add(new DEROctetString(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent()))); 
		return new DERSequence(sigPolicyStore);
	}
	
	private void assertSignaturePolicyStoreExtensionPossible(SignerInformation signerInformation) {
		if (CMSUtils.containsATSTv2(signerInformation)) {
			throw new IllegalInputException("Cannot add signature policy store to a CAdES containing an archiveTimestampV2");
		}
	}

}
