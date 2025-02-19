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
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
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
	 * This object is used to create data container objects such as an OutputStream or a DSSDocument
	 */
	protected DSSResourcesHandlerBuilder resourcesHandlerBuilder = CAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER;

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

	/**
	 * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
	 * during the signature creation procedure.
	 * NOTE: The {@code DSSResourcesHandlerBuilder} is supported only within the 'dss-cms-stream' module!
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
		this.resourcesHandlerBuilder = CMSUtils.getDSSResourcesHandlerBuilder(resourcesHandlerBuilder);
	}

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, CAdESSignatureParameters parameters) {
		Objects.requireNonNull(tspSource, "A TSPSource is required !");

		DigestAlgorithm digestAlgorithm = parameters.getContentTimestampParameters().getDigestAlgorithm();
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, toSignDocument.getDigestValue(digestAlgorithm));
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
		
		assertSigningCertificateValid(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

		final CMS originalCms = getOriginalCMS(toSignDocument, parameters);
		final DSSDocument contentToSign = getContentToSign(toSignDocument, parameters, originalCms);

		final SignerInfoGenerator signerInfoGenerator = new CMSSignerInfoGeneratorBuilder()
				.build(contentToSign, parameters, customContentSigner);

		final CMSBuilder cmsBuilder = getCMSBuilder(parameters).setOriginalCMS(originalCms);
		CMS cms = cmsBuilder.createCMS(signerInfoGenerator, contentToSign);
		CMSUtils.writeToDSSDocument(cms, resourcesHandlerBuilder);

		final byte[] bytes = customContentSigner.getOutputStream().toByteArray();
		return new ToBeSigned(bytes);
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");

		assertSigningCertificateValid(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		signatureValue = ensureSignatureValue(signatureAlgorithm, signatureValue);

		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
		final CMS originalCms = getOriginalCMS(toSignDocument, parameters);
		if (originalCms == null && SignaturePackaging.DETACHED.equals(packaging) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
			parameters.getContext().setDetachedContents(Collections.singletonList(toSignDocument));
		}
		final DSSDocument contentToSign = getContentToSign(toSignDocument, parameters, originalCms);

		final SignerInfoGenerator signerInfoGenerator = new CMSSignerInfoGeneratorBuilder()
				.setIncludeUnsignedAttributes(true)
				.build(contentToSign, parameters, customContentSigner);

		final CMSBuilder cmsBuilder = getCMSBuilder(parameters).setOriginalCMS(originalCms);
		CMS cms = cmsBuilder.createCMS(signerInfoGenerator, contentToSign);

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		if (!SignatureLevel.CAdES_BASELINE_B.equals(signatureLevel)) {
			// Only the last signature will be extended
			final SignerInformation newSignerInformation = getNewSignerInformation(originalCms, cms);
			final CAdESSignatureExtension extension = getExtensionProfile(parameters);
			cms = extension.extendCMSSignatures(cms, newSignerInformation, parameters);
		}

		DSSDocument signature = CMSUtils.writeToDSSDocument(cms, resourcesHandlerBuilder);
		signature.setName(getFinalFileName(toSignDocument, SigningOperation.SIGN,
				parameters.getSignatureLevel(), parameters.getSignaturePackaging()));
		parameters.reinit();
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
	 * This method retrieves the data to be signed. If this data is located within a signature then it is extracted.
	 *
	 * @param toSignDocument
	 *            document to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param originalCms
	 *            the signed data extracted from an existing signature or null
	 * @return {@link DSSDocument} toSignData
	 */
	private DSSDocument getContentToSign(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters,
										 final CMS originalCms) {
		final List<DSSDocument> detachedContents = parameters.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			// * CAdES only can sign one document
			// * ASiC-S -> the document to sign or package.zip
			// * ASiC-E -> ASiCManifest
			return detachedContents.get(0);
		} else {
			if (originalCms == null) {
				return toSignDocument;
			} else {
				return getSignedContent(originalCms);
			}
		}
	}

	/**
	 * This method returns the signed content of CMSSignedData.
	 *
	 * @param cms
	 *            the already signed {@code CMS}
	 * @return the original toSignDocument or null
	 */
	private DSSDocument getSignedContent(final CMS cms) {
		if (cms.isDetachedSignature()) {
			throw new IllegalArgumentException("Detached content shall be provided on parallel signing of a detached signature! " +
					"Please use cadesSignatureParameters#setDetachedContents method to provide original files.");
		}
		return cms.getSignedContent();
	}
	
	private SignerInformation getNewSignerInformation(CMS originalCMS, CMS newCMS) {
		Collection<SignerInformation> signers = newCMS.getSignerInfos().getSigners();
		if (originalCMS != null) {
			for (SignerInformation signerInformation : signers) {
				if (!containsSignerInfo(originalCMS, signerInformation)) {
					return signerInformation;
				}
			}
		}
		// return the first one if originalSignedData is null (single signature creation)
		return signers.iterator().next();
	}
	
	private boolean containsSignerInfo(CMS cms, SignerInformation signerInformationToFind) {
		for (SignerInformation signerInformation : cms.getSignerInfos()) {
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
	 * @return {@code CAdESSignatureExtension} related to the pre-defined profile
	 */
	private CAdESSignatureExtension getExtensionProfile(final CAdESSignatureParameters parameters) {
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");
		CAdESSignatureExtension cadesSignatureExtension;
		switch (signatureLevel) {
			case CAdES_BASELINE_T:
				cadesSignatureExtension = new CAdESLevelBaselineT(tspSource, certificateVerifier);
				break;
			case CAdES_BASELINE_LT:
				cadesSignatureExtension = new CAdESLevelBaselineLT(tspSource, certificateVerifier);
				break;
			case CAdES_BASELINE_LTA:
				cadesSignatureExtension = new CAdESLevelBaselineLTA(tspSource, certificateVerifier);
				break;
			default:
				throw new UnsupportedOperationException(
						String.format("Unsupported signature format '%s' for extension.", signatureLevel));
		}
		cadesSignatureExtension.setResourcesHandlerBuilder(resourcesHandlerBuilder);
		return cadesSignatureExtension;
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
	private CMS getOriginalCMS(final DSSDocument dssDocument, final CAdESSignatureParameters parameters) {
		CMS cms = null;
		if (parameters.isParallelSignature() && !(dssDocument instanceof DigestDocument)
				&& DSSASN1Utils.isASN1SequenceTag(DSSUtils.readFirstByte(dssDocument))) {
			try {
				cms = CMSUtils.parseToCMS(dssDocument);
			} catch (Exception e) {
				// not a parallel signature
			}
			if (cms != null) {
				assertSignaturePossible(cms, parameters);
			}
		}
		return cms;
	}

	private void assertSignaturePossible(final CMS cms, final CAdESSignatureParameters parameters) {
		if (cms.isDetachedSignature() != (SignaturePackaging.DETACHED == parameters.getSignaturePackaging())) {
			throw new IllegalArgumentException(String.format("Unable to create a parallel signature with packaging '%s'" +
					" which is different than the one used in the original signature!", parameters.getSignaturePackaging()));
		}
	}

	private CMSBuilder getCMSBuilder(CAdESSignatureParameters parameters) {
		return new CMSBuilder()
				.setSigningCertificate(parameters.getSigningCertificate())
				.setCertificateChain(parameters.getCertificateChain())
				.setGenerateWithoutCertificates(parameters.isGenerateTBSWithoutCertificate())
				.setTrustAnchorBPPolicy(parameters.bLevel().isTrustAnchorBPPolicy())
				.setTrustedCertificateSource(certificateVerifier.getTrustedCertSources())
				.setEncapsulate(isEncapsulateSignerData(parameters));
	}

	private boolean isEncapsulateSignerData(CAdESSignatureParameters signatureParameters) {
		return !SignaturePackaging.DETACHED.equals(signatureParameters.getSignaturePackaging());
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

		final CAdESSignaturePolicyStoreBuilder builder = getCAdESSignaturePolicyStoreBuilder();
		DSSDocument documentWithPolicyStore = builder.addSignaturePolicyStore(document, signaturePolicyStore);
		documentWithPolicyStore.setName(getFinalFileName(document, SigningOperation.EXTEND, null));
		return documentWithPolicyStore;
	}

	/**
	 * Loads the relevant {@code CAdESSignaturePolicyStoreBuilder}
	 *
	 * @return {@link CAdESSignaturePolicyStoreBuilder}
	 */
	protected CAdESSignaturePolicyStoreBuilder getCAdESSignaturePolicyStoreBuilder() {
		CAdESSignaturePolicyStoreBuilder builder = new CAdESSignaturePolicyStoreBuilder();
		builder.setResourcesHandlerBuilder(resourcesHandlerBuilder);
		return builder;
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "parameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The signature to be counter-signed must be specified");
		assertSigningCertificateValid(parameters);
		assertCounterSignaturePossible(parameters);

		final CAdESCounterSignatureBuilder counterSignatureBuilder = getCAdESCounterSignatureBuilder();
		final SignerInformation signerInfoToCounterSign = counterSignatureBuilder
				.getSignerInformationToBeCounterSigned(signatureDocument, parameters);
		
		return getDataToBeCounterSigned(signerInfoToCounterSign, parameters);
	}
	
	/**
	 * Returns a data toBeSigned for a counter signature on the given {@code signerInfoToCounterSign}
	 *
	 * @param signerInfoToCounterSign {@link SignerInformation} to counter-sign
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link ToBeSigned}
	 */
	public ToBeSigned getDataToBeCounterSigned(SignerInformation signerInfoToCounterSign,
												  CAdESSignatureParameters parameters) {
		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());

		final CAdESCounterSignatureBuilder counterSignatureBuilder = getCAdESCounterSignatureBuilder();
		counterSignatureBuilder.generateCounterSignature(signerInfoToCounterSign, parameters, customContentSigner);

		return new ToBeSigned(customContentSigner.getOutputStream().toByteArray());
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument signatureDocument, CAdESCounterSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(signatureDocument, "signatureDocument cannot be null!");
		Objects.requireNonNull(parameters, "parameters cannot be null!");
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The signature to be counter-signed must be specified");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		assertSigningCertificateValid(parameters);
		assertCounterSignaturePossible(parameters);
		signatureValue = ensureSignatureValue(parameters.getSignatureAlgorithm(), signatureValue);

		CMS originalCMS = CMSUtils.parseToCMS(signatureDocument);
		
		final CAdESCounterSignatureBuilder counterSignatureBuilder = getCAdESCounterSignatureBuilder();
		DSSDocument counterSigned = counterSignatureBuilder.addCounterSignature(originalCMS, parameters, signatureValue);
		counterSigned.setName(getFinalFileName(signatureDocument, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel()));
		counterSigned.setMimeType(signatureDocument.getMimeType());
		
		return counterSigned;
	}

	/**
	 * Loads the relevant {@code CAdESCounterSignatureBuilder}
	 *
	 * @return {@link CAdESCounterSignatureBuilder}
	 */
	protected CAdESCounterSignatureBuilder getCAdESCounterSignatureBuilder() {
		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		counterSignatureBuilder.setResourcesHandlerBuilder(resourcesHandlerBuilder);
		return counterSignatureBuilder;
	}

	private void assertCounterSignaturePossible(CAdESCounterSignatureParameters parameters) {
		if (!SignatureLevel.CAdES_BASELINE_B.equals(parameters.getSignatureLevel())) {
			throw new UnsupportedOperationException(String.format("A counter signature with a level '%s' is not supported! "
					+ "Please, use CAdES-BASELINE-B", parameters.getSignatureLevel()));
		}
	}

}
