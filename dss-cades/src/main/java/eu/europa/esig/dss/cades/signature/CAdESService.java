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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * CAdES implementation of DocumentSignatureService
 */
public class CAdESService extends
		AbstractSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> 
		implements CounterSignatureService<CAdESCounterSignatureParameters> {

	private static final long serialVersionUID = -7744554779153433450L;

	private static final Logger LOG = LoggerFactory.getLogger(CAdESService.class);

	/**
	 * This is the constructor to create an instance of the {@code CAdESService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public CAdESService(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ CAdESService created");
	}

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, CAdESSignatureParameters parameters) {
		Objects.requireNonNull(tspSource, "A TSPSource is required !");

		DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, Utils.fromBase64(toSignDocument.getDigest(digestAlgorithm)));
		try {
			return new TimestampToken(timeStampResponse.getBytes(), TimestampType.CONTENT_TIMESTAMP);
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException("Cannot create a content TimestampToken", e);
		}
	}

	@Override
	public ToBeSigned getDataToSign(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		
		assertSigningDateInCertificateValidityRange(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());
		final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(toSignDocument, parameters.getReferenceDigestAlgorithm());

		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(dcp, parameters, false);
		final CMSSignedData originalCmsSignedData = getCmsSignedData(toSignDocument, parameters);

		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, originalCmsSignedData);

		final DSSDocument toSignData = getToSignData(toSignDocument, parameters, originalCmsSignedData);
		final CMSTypedData content = CMSUtils.getContentToBeSigned(toSignData);
		final boolean encapsulate = !SignaturePackaging.DETACHED.equals(packaging);
		CMSUtils.generateCMSSignedData(cmsSignedDataGenerator, content, encapsulate);
		final byte[] bytes = customContentSigner.getOutputStream().toByteArray();
		return new ToBeSigned(bytes);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");

		assertSigningDateInCertificateValidityRange(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		signatureValue = ensureSignatureValue(signatureAlgorithm, signatureValue);

		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
		final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(toSignDocument, parameters.getReferenceDigestAlgorithm());

		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(dcp, parameters, true);
		final CMSSignedData originalCmsSignedData = getCmsSignedData(toSignDocument, parameters);
		if ((originalCmsSignedData == null) && SignaturePackaging.DETACHED.equals(packaging) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
			parameters.setDetachedContents(Arrays.asList(toSignDocument));
		}

		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, originalCmsSignedData);

		final DSSDocument toSignData = getToSignData(toSignDocument, parameters, originalCmsSignedData);
		final CMSTypedData content = CMSUtils.getContentToBeSigned(toSignData);

		final boolean encapsulate = !SignaturePackaging.DETACHED.equals(packaging);
		final CMSSignedData cmsSignedData = CMSUtils.generateCMSSignedData(cmsSignedDataGenerator, content, encapsulate);
		DSSDocument signature = new CMSSignedDocument(cmsSignedData);

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		if (!SignatureLevel.CAdES_BASELINE_B.equals(signatureLevel)) {
			// Only the last signature will be extended
			final SignerInformation newSignerInformation = getNewSignerInformation(originalCmsSignedData, cmsSignedData);
			final CAdESSignatureExtension extension = getExtensionProfile(parameters);
			CMSSignedData extendedCMSSignature = extension.extendCMSSignatures(cmsSignedData, newSignerInformation, parameters);
			signature = new CMSSignedDocument(extendedCMSSignature);
		}
		signature.setName(getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		parameters.reinitDeterministicId();
		return signature;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final CAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");
		// false: All signature are extended
		final CAdESSignatureExtension extension = getExtensionProfile(parameters);
		final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
		dssDocument.setName(getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel()));
		return dssDocument;
	}

	/**
	 * This method retrieves the data to be signed. It this data is located within a signature then it is extracted.
	 *
	 * @param toSignDocument
	 *            document to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param originalCmsSignedData
	 *            the signed data extracted from an existing signature or null
	 * @return {@link DSSDocument} toSignData
	 */
	private DSSDocument getToSignData(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters, final CMSSignedData originalCmsSignedData) {
		final List<DSSDocument> detachedContents = parameters.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			// CAdES only can sign one document
			// (ASiC-S -> the document to sign /
			// ASiC-E -> ASiCManifest)
			return detachedContents.get(0);
		} else {
			if (originalCmsSignedData == null) {
				return toSignDocument;
			} else {
				return getSignedContent(originalCmsSignedData);
			}
		}
	}

	/**
	 * This method returns the signed content of CMSSignedData.
	 *
	 * @param cmsSignedData
	 *            the already signed {@code CMSSignedData}
	 * @return the original toSignDocument or null
	 */
	private DSSDocument getSignedContent(final CMSSignedData cmsSignedData) {
		final CMSTypedData signedContent = cmsSignedData.getSignedContent();
		if (signedContent == null) {
			throw new DSSException("Unknown SignedContent");
		}
		final byte[] documentBytes = (byte[]) signedContent.getContent();
		return new InMemoryDocument(documentBytes);
	}
	
	private SignerInformation getNewSignerInformation(CMSSignedData originalSignedData, CMSSignedData cmsSignedData) {
		Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
		if (originalSignedData != null) {
			for (SignerInformation signerInformation : signers) {
				if (!containsSignerInfo(originalSignedData, signerInformation)) {
					return signerInformation;
				}
			}
		}
		// return the first one if originalSignedData is null (single signature creation)
		return signers.iterator().next();
	}
	
	private boolean containsSignerInfo(CMSSignedData signedData, SignerInformation signerInformationToFind) {
		for (SignerInformation signerInformation : signedData.getSignerInfos()) {
			if (signerInformationToFind.toASN1Structure() == signerInformation.toASN1Structure()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method returns the extension profile to be used for a CAdES signature augmentation
	 *
	 * @param parameters
	 *            set of driving signing parameters
	 * @return {@code CAdESSignatureExtension} related to the predefine profile
	 */
	private CAdESSignatureExtension getExtensionProfile(final CAdESSignatureParameters parameters) {
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");
		switch (signatureLevel) {
			case CAdES_BASELINE_T:
				return new CAdESLevelBaselineT(tspSource);
			case CAdES_BASELINE_LT:
				return new CAdESLevelBaselineLT(tspSource, certificateVerifier);
			case CAdES_BASELINE_LTA:
				return new CAdESLevelBaselineLTA(tspSource, certificateVerifier);
			default:
				throw new IllegalArgumentException("Unsupported signature format : " + signatureLevel);
		}
	}

	/**
	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
	 *
	 * @param dssDocument
	 *            {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
	 * @param parameters
	 *            set of driving signing parameters
	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
	 */
	private CMSSignedData getCmsSignedData(final DSSDocument dssDocument, final CAdESSignatureParameters parameters) {
		CMSSignedData cmsSignedData = null;
		if (!(dssDocument instanceof DigestDocument) && DSSASN1Utils.isASN1SequenceTag(DSSUtils.readFirstByte(dssDocument))) {
			try {
				cmsSignedData = new CMSSignedData(DSSUtils.toByteArray(dssDocument));
				if (SignaturePackaging.ENVELOPING == parameters.getSignaturePackaging() && cmsSignedData.getSignedContent().getContent() == null) {
					cmsSignedData = null;
				}
			} catch (Exception e) {
				// not a parallel signature
			}
		}
		return cmsSignedData;
	}

	/**
	 * @param packaging
	 *            {@code SignaturePackaging} to be checked
	 * @throws DSSException
	 *             if the packaging is not supported for this kind of signature
	 */
	private void assertSignaturePackaging(final SignaturePackaging packaging) {
		if ((packaging != SignaturePackaging.ENVELOPING) && (packaging != SignaturePackaging.DETACHED)) {
			throw new IllegalArgumentException("Unsupported signature packaging: " + packaging);
		}
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the CAdES Signature
	 * 
	 * @param document             {@link DSSDocument} containing a CAdES Signature
	 *                             to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} CAdESSignature with an incorporated SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(document, "The document cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");

		CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(document);

		CAdESSignaturePolicyStoreBuilder builder = new CAdESSignaturePolicyStoreBuilder();
		CMSSignedData newCmsSignedData = builder.addSignaturePolicyStore(cmsSignedData, signaturePolicyStore);
		
		CMSSignedDocument documentWithPolicyStore = new CMSSignedDocument(newCmsSignedData);
		documentWithPolicyStore.setName(getFinalFileName(document, SigningOperation.EXTEND, null));
		return documentWithPolicyStore;
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "parameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The signature to be counter-signed must be specified");
		assertSigningDateInCertificateValidityRange(parameters);
		assertCounterSignaturePossible(parameters);

		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		SignerInformation signerInfoToCounterSign = counterSignatureBuilder.getSignerInformationToBeCounterSigned(signatureDocument, parameters);
		
		return getDataToBeCounterSigned(signatureDocument, signerInfoToCounterSign, parameters);
	}
	
	/**
	 * Returns a data toBeSigned for a counter signature on the given {@code signerInfoToCounterSign}
	 * 
	 * @param signatureDocument {@link DSSDocument} containing a signature to be counter signed
	 * @param signerInfoToCounterSign {@link SignerInformation} to counter sign
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link ToBeSigned}
	 */
	public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, SignerInformation signerInfoToCounterSign, 
			CAdESSignatureParameters parameters) {
		InMemoryDocument toSignDocument = new InMemoryDocument(signerInfoToCounterSign.getSignature());

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());
		final DigestCalculatorProvider dcp = CMSUtils.getDigestCalculatorProvider(toSignDocument, parameters.getReferenceDigestAlgorithm());

		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(dcp, parameters, false);

		CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, cmsSignedData);
		CMSUtils.generateCounterSigners(cmsSignedDataGenerator, signerInfoToCounterSign);
		return new ToBeSigned(customContentSigner.getOutputStream().toByteArray());
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "parameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The signature to be counter-signed must be specified");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		assertSigningDateInCertificateValidityRange(parameters);
		assertCounterSignaturePossible(parameters);
		signatureValue = ensureSignatureValue(parameters.getSignatureAlgorithm(), signatureValue);

		CMSSignedData originalCMSSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		
		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		CMSSignedDocument counterSigned = counterSignatureBuilder.addCounterSignature(originalCMSSignedData, parameters, signatureValue);
		counterSigned.setName(getFinalFileName(signatureDocument, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel()));
		counterSigned.setMimeType(signatureDocument.getMimeType());
		
		return counterSigned;
	}

	private void assertCounterSignaturePossible(CAdESCounterSignatureParameters parameters) {
		if (!SignatureLevel.CAdES_BASELINE_B.equals(parameters.getSignatureLevel())) {
			throw new UnsupportedOperationException(String.format("A counter signature with a level '%s' is not supported! "
					+ "Please, use CAdES-BASELINE-B", parameters.getSignatureLevel()));
		}
	}

}
