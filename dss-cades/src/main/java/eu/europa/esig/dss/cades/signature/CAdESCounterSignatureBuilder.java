package eu.europa.esig.dss.cades.signature;

import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class CAdESCounterSignatureBuilder {

	public SignerInformation getSignerInformationToBeSigned(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		String signatureIdToCounterSign = parameters.getSignatureIdToCounterSign();
		Objects.requireNonNull(signatureIdToCounterSign, "The signature to be counter-signed must be specified");

		CAdESSignature cadesSignature = getSignatureById(signatureDocument, signatureIdToCounterSign);
		if (cadesSignature == null) {
			throw new DSSException(String.format("CAdESSignature not found with the given dss id '%s'", signatureIdToCounterSign));
		}
		return cadesSignature.getSignerInformation();
	}

//	public DSSDocument counterSignSignature(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
//
//		SignatureAlgorithm signatureAlgorithm = signatureValue.getAlgorithm();
//
//		CAdESSignature masterSignature = getSignatureById(signatureDocument, parameters.getSignatureIdToCounterSign());
//
//		CMSSignedData masterCmsSignedData = masterSignature.getCmsSignedData();
//		SignerInformationStore masterSignerInfos = masterCmsSignedData.getSignerInfos();
//
//		SignerInformation masterSignerInformation = masterSignature.getSignerInformation();
//		SignerId masterSignerId = masterSignature.getSignerId();
//
//		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
//
//		Collection<SignerInformation> counterSignatureInformationCollection = new ArrayList<SignerInformation>();
//		counterSignatureInformationCollection.add(updatedMasterSignerInformation);
//		SignerInformationStore counterSignatureInformationStore = new SignerInformationStore(counterSignatureInformationCollection);
//		
//		SignerInformation updatedMasterSignerInformation = SignerInformation.addCounterSigners(masterSignerInformation, counterSignatureInformationStore);
//
//		CMSSignedData updatedMaster = CMSSignedData.replaceSigners(masterCmsSignedData, signerInformationStore);
//		return new CMSSignedDocument(updatedMaster);
//	}

	public CAdESSignature getSignatureById(DSSDocument signatureDocument, String dssId) {
		CMSDocumentValidator validator = new CMSDocumentValidator(signatureDocument);
		List<AdvancedSignature> signatures = validator.getSignatures();
		return findSignatureRecursive(signatures, dssId);
	}

	private CAdESSignature findSignatureRecursive(List<AdvancedSignature> signatures, String dssId) {
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature advancedSignature : signatures) {
				if (dssId.equals(advancedSignature.getId())) {
					return (CAdESSignature) advancedSignature;
				}
				findSignatureRecursive(advancedSignature.getCounterSignatures(), dssId);
			}
		}
		return null;
	}

}
