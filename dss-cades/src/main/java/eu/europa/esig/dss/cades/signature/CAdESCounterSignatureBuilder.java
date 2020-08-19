package eu.europa.esig.dss.cades.signature;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;

public class CAdESCounterSignatureBuilder {

	private final CertificateVerifier certificateVerifier;

	public CAdESCounterSignatureBuilder(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	public CMSSignedData recursivelyAddCounterSignature(CMSSignedData originalCMSSignedData,
			SignerInformationStore signerInfos, CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
		for (SignerInformation signerInformation : signerInfos.getSigners()) {
			CAdESSignature cades = new CAdESSignature(originalCMSSignedData, signerInformation);
			if (Utils.areStringsEqual(cades.getId(), parameters.getSignatureIdToCounterSign())) {

				SignerInformationStore counterSignatureSignerInfoStore = generateCounterSignature(signerInformation, parameters, signatureValue);

				return addCounterSignature(originalCMSSignedData, signerInformation, counterSignatureSignerInfoStore);
			} else if (signerInformation.getCounterSignatures().size() > 0) {
				return recursivelyAddCounterSignature(originalCMSSignedData, signerInformation.getCounterSignatures(), parameters, signatureValue);
			}
		}
		throw new DSSException(String.format("(Counter-)signature with id '%s' is not found", parameters.getSignatureIdToCounterSign()));
	}

	private CMSSignedData addCounterSignature(CMSSignedData originalCMSSignedData, SignerInformation signerInformation,
			SignerInformationStore counterSignatureSignerInfoStore) {
		Collection<SignerInformation> signerInformationCollection = originalCMSSignedData.getSignerInfos().getSigners();
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		for (SignerInformation currentSignerInfo : signerInformationCollection) {
			if (currentSignerInfo.equals(signerInformation)) {
				newSignerInformationList.add(SignerInformation.addCounterSigners(signerInformation, counterSignatureSignerInfoStore));
			} else {
				newSignerInformationList.add(currentSignerInfo);
			}
		}

		SignerInformationStore signerInformationStore = new SignerInformationStore(newSignerInformationList);
		return CMSSignedData.replaceSigners(originalCMSSignedData, signerInformationStore);
	}

	private SignerInformationStore generateCounterSignature(SignerInformation signerInformation, CAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		CMSSignedDataBuilder builder = new CMSSignedDataBuilder(certificateVerifier);

		SignatureAlgorithm signatureAlgorithm = signatureValue.getAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

		final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(new InMemoryDocument(signerInformation.getSignature()),
				parameters.getReferenceDigestAlgorithm());
		SignerInfoGeneratorBuilder signerInformationGeneratorBuilder = builder.getSignerInfoGeneratorBuilder(dcp, parameters, false);
		CMSSignedDataGenerator cmsSignedDataGenerator = builder.createCMSSignedDataGenerator(parameters, customContentSigner, signerInformationGeneratorBuilder,
				null);
		return CMSUtils.generateCounterSigners(cmsSignedDataGenerator, signerInformation);
	}

	public SignerInformation getSignerInformationToBeSigned(DSSDocument signatureDocument, String signatureIdToCounterSign) {
		CAdESSignature cadesSignature = getSignatureById(signatureDocument, signatureIdToCounterSign);
		if (cadesSignature == null) {
			throw new DSSException(String.format("CAdESSignature not found with the given dss id '%s'", signatureIdToCounterSign));
		}
		return cadesSignature.getSignerInformation();
	}

	private CAdESSignature getSignatureById(DSSDocument signatureDocument, String dssId) {
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
