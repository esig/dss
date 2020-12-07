package eu.europa.esig.dss.cades.signature;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestFile;

public class CAdESCounterSignatureBuilder {

	private final CertificateVerifier certificateVerifier;
	
	/** A signature signed manifest. Used for ASiC */
	private ManifestFile manifestFile;

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

		if (Utils.isCollectionNotEmpty(updatedSignerInfo)) {
			CMSSignedData updatedCMSSignedData = CMSSignedData.replaceSigners(originalCMSSignedData, new SignerInformationStore(updatedSignerInfo));
			updatedCMSSignedData = addNewCertificates(updatedCMSSignedData, originalCMSSignedData, parameters);
			return new CMSSignedDocument(updatedCMSSignedData);
		} else {
			throw new DSSException("No updated signed info");
		}
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

				SignerInformationStore counterSignatureSignerInfoStore = generateCounterSignature(originalCMSSignedData, signerInformation, parameters,
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
	private CMSSignedData addNewCertificates(CMSSignedData updatedCMSSignedData, CMSSignedData originalCMSSignedData,
			CAdESCounterSignatureParameters parameters) {
		final List<CertificateToken> certificateTokens = new LinkedList<>();
		Store<X509CertificateHolder> certificatesStore = originalCMSSignedData.getCertificates();
		final Collection<X509CertificateHolder> certificatesMatches = certificatesStore.getMatches(null);
		for (final X509CertificateHolder certificatesMatch : certificatesMatches) {
			final CertificateToken token = DSSASN1Utils.getCertificate(certificatesMatch);
			if (!certificateTokens.contains(token)) {
				certificateTokens.add(token);
			}
		}

		BaselineBCertificateSelector certificateSelectors = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> newCertificates = certificateSelectors.getCertificates();
		for (CertificateToken certificateToken : newCertificates) {
			if (!certificateTokens.contains(certificateToken)) {
				certificateTokens.add(certificateToken);
			}
		}

		final Collection<X509Certificate> certs = new ArrayList<>();
		for (final CertificateToken certificateInChain : certificateTokens) {
			certs.add(certificateInChain.getCertificate());
		}
		
		Store<X509CRLHolder> crlsStore = originalCMSSignedData.getCRLs();
		final Collection<Encodable> crls = new HashSet<>(crlsStore.getMatches(null));
		Store ocspBasicStore = originalCMSSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		for (Object ocsp : ocspBasicStore.getMatches(null)) {
			crls.add(new OtherRevocationInfoFormat(OCSPObjectIdentifiers.id_pkix_ocsp_basic, (ASN1Encodable) ocsp));
		}
		Store ocspResponseStore = originalCMSSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
		for (Object ocsp : ocspResponseStore.getMatches(null)) {
			crls.add(new OtherRevocationInfoFormat(CMSObjectIdentifiers.id_ri_ocsp_response, (ASN1Encodable) ocsp));
		}

		try {
			JcaCertStore jcaCertStore = new JcaCertStore(certs);
			return CMSSignedData.replaceCertificatesAndCRLs(updatedCMSSignedData, jcaCertStore, originalCMSSignedData.getAttributeCertificates(),
					new CollectionStore(crls));
		} catch (Exception e) {
			throw new DSSException("Unable to create the JcaCertStore", e);
		}
	}

	private SignerInformationStore generateCounterSignature(CMSSignedData originalCMSSignedData, SignerInformation signerInformation,
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
			throw new DSSException(String.format("CAdESSignature not found with the given dss id '%s'", parameters.getSignatureIdToCounterSign()));
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
			throw new DSSException("Cannot add a counter signature to a CAdES containing an archiveTimestampV2");
		}
	}

}
