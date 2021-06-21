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
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.ValidationData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;

import java.util.LinkedList;
import java.util.List;

/**
 * The class to build a CAdES counter signature
 */
public class CAdESCounterSignatureBuilder {

	/** The certificateVerifier to use */
	private final CertificateVerifier certificateVerifier;
	
	/** A signature signed manifest. Used for ASiC */
	private ManifestFile manifestFile;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESCounterSignatureBuilder(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Sets a signed manifest file
	 * NOTE: ASiC only
	 * 
	 * @param manifestFile {@link ManifestFile}
	 */
	public void setManifestFile(ManifestFile manifestFile) {
		this.manifestFile = manifestFile;
	}

	/**
	 * Adds a counter signature the provided CMSSignedData
	 * 
	 * @param originalCMSSignedData {@link CMSSignedData} to add a counter signature into
	 * @param parameters {@link CAdESCounterSignatureParameters}
	 * @param signatureValue {@link SignatureValue}
	 * @return {@link CMSSignedDocument} with an added counter signature
	 */
	public CMSSignedDocument addCounterSignature(CMSSignedData originalCMSSignedData, CAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {

		final List<SignerInformation> updatedSignerInfo = getUpdatedSignerInformations(originalCMSSignedData, originalCMSSignedData.getSignerInfos(),
				parameters, signatureValue, null);

		CMSSignedData updatedCMSSignedData = CMSSignedData.replaceSigners(originalCMSSignedData, new SignerInformationStore(updatedSignerInfo));
		updatedCMSSignedData = addNewCertificates(updatedCMSSignedData, parameters);
		return new CMSSignedDocument(updatedCMSSignedData);
	}

	private List<SignerInformation> getUpdatedSignerInformations(CMSSignedData originalCMSSignedData, SignerInformationStore signerInformationStore,
			CAdESCounterSignatureParameters parameters, SignatureValue signatureValue, CAdESSignature masterSignature) {

		List<SignerInformation> result = new LinkedList<>();
		for (SignerInformation signerInformation : signerInformationStore) {
			CAdESSignature cades = new CAdESSignature(originalCMSSignedData, signerInformation);
			cades.setMasterSignature(masterSignature);
			cades.setDetachedContents(parameters.getDetachedContents());
			cades.setManifestFile(manifestFile);
			
			if (Utils.areStringsEqual(cades.getId(), parameters.getSignatureIdToCounterSign())) {
				if (masterSignature != null) {
					throw new UnsupportedOperationException("Cannot recursively add a counter-signature");
				}
				assertCounterSignaturePossible(signerInformation);

				SignerInformationStore counterSignatureSignerInfoStore = generateCounterSignature(signerInformation, parameters,
						signatureValue);

				result.add(SignerInformation.addCounterSigners(signerInformation, counterSignatureSignerInfoStore));

			} else if (signerInformation.getCounterSignatures().size() > 0) {
				List<SignerInformation> updatedSignerInformations = getUpdatedSignerInformations(originalCMSSignedData,
						signerInformation.getCounterSignatures(), parameters, signatureValue, cades);
				result.add(SignerInformation.addCounterSigners(signerInformation, new SignerInformationStore(updatedSignerInformations)));
				
			} else {
				result.add(signerInformation);
			}
		}

		return result;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private CMSSignedData addNewCertificates(CMSSignedData updatedCMSSignedData, CAdESCounterSignatureParameters parameters) {
		ValidationData validationDataToAdd = new ValidationData();

		BaselineBCertificateSelector certificateSelectors = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> newCertificates = certificateSelectors.getCertificates();
		for (CertificateToken certificateToken : newCertificates) {
			validationDataToAdd.addToken(certificateToken);
		}

		CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		return cmsSignedDataBuilder.extendCMSSignedData(updatedCMSSignedData, validationDataToAdd);
	}

	private SignerInformationStore generateCounterSignature(SignerInformation signerInformation,
			CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
		CMSSignedDataBuilder builder = new CMSSignedDataBuilder(certificateVerifier);

		SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

		final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(new InMemoryDocument(signerInformation.getSignature()),
				parameters.getReferenceDigestAlgorithm());
		SignerInfoGeneratorBuilder signerInformationGeneratorBuilder = builder.getSignerInfoGeneratorBuilder(dcp, parameters, false);
		CMSSignedDataGenerator cmsSignedDataGenerator = builder.createCMSSignedDataGenerator(parameters, customContentSigner, signerInformationGeneratorBuilder,
				null);
		return CMSUtils.generateCounterSigners(cmsSignedDataGenerator, signerInformation);
	}

	/**
	 * Returns a {@code SignerInformation} to be counter signed
	 * 
	 * @param signatureDocument {@link DSSDocument} to find the related signature
	 * @param parameters {@link CAdESCounterSignatureParameters}
	 * @return {@link SignerInformation}
	 */
	public SignerInformation getSignerInformationToBeCounterSigned(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		CAdESSignature cadesSignature = getSignatureById(signatureDocument, parameters);
		if (cadesSignature == null) {
			throw new IllegalArgumentException(String.format("CAdESSignature not found with the given dss id '%s'",
					parameters.getSignatureIdToCounterSign()));
		}
		return cadesSignature.getSignerInformation();
	}

	private CAdESSignature getSignatureById(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		CMSDocumentValidator validator = new CMSDocumentValidator(signatureDocument);
		validator.setDetachedContents(parameters.getDetachedContents());
		validator.setManifestFile(manifestFile);
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		return findSignatureRecursive(signatures, parameters.getSignatureIdToCounterSign());
	}

	private CAdESSignature findSignatureRecursive(List<AdvancedSignature> signatures, String signatureId) {
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature advancedSignature : signatures) {
				if (signatureId.equals(advancedSignature.getId())) {
					CAdESSignature cades = (CAdESSignature) advancedSignature;
					assertCounterSignaturePossible(cades.getSignerInformation());
					return cades;
				}
				
				CAdESSignature counterSignatureById = findSignatureRecursive(advancedSignature.getCounterSignatures(), signatureId);
				if (counterSignatureById != null) {
					// TODO : add a nested counter signature support + check if a master signature is not timestamped
					throw new UnsupportedOperationException("Nested counter signatures are not supported with CAdES!");
				}
			}
		}
		return null;
	}
	
	private void assertCounterSignaturePossible(SignerInformation signerInformation) {
		if (CMSUtils.containsATSTv2(signerInformation)) {
			throw new IllegalInputException("Cannot add a counter signature to a CAdES containing an archiveTimestampV2");
		}
	}

}
