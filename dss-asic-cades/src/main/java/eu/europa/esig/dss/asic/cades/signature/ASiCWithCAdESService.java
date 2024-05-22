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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.extract.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.timestamp.ASiCWithCAdESTimestampService;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureBuilder;
import eu.europa.esig.dss.cades.signature.CAdESCounterSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * The service containing the main methods for ASiC with CAdES signature creation/extension
 *
 */
@SuppressWarnings("serial")
public class ASiCWithCAdESService extends AbstractASiCSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters, 
						CAdESCounterSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESService.class);

	/**
	 * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
	 */
	private ASiCWithCAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithCAdESFilenameFactory();

	/**
	 * The default constructor to instantiate the service
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public ASiCWithCAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with CAdES created");
	}

	/**
	 * Sets {@code ASiCWithCAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
	 * such as signature files.
	 *
	 * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
	 */
	public void setAsicFilenameFactory(ASiCWithCAdESFilenameFactory asicFilenameFactory) {
		Objects.requireNonNull(asicFilenameFactory, "ASiCWithCAdESFilenameFactory cannot be null!");
		this.asicFilenameFactory = asicFilenameFactory;
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSignaturePossible(toSignDocuments);

		ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESSignatureDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);
		DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();
		return getCAdESService().getContentTimestamp(toBeSigned, parameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSignaturePossible(toSignDocuments);
		assertSigningCertificateValid(parameters);

		ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESSignatureDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);
		assertSignaturePossible(asicContent.getTimestampDocuments(), parameters.aSiC());

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.getContext().setDetachedContents(dataToSignHelper.getDetachedContents());

		DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();
		return getCAdESService().getDataToSign(toBeSigned, cadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithCAdESSignatureParameters parameters,
									SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		assertSignaturePossible(toSignDocuments);
		assertSigningCertificateValid(parameters);

		ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithCAdESHelper dataToSignHelper = new ASiCWithCAdESSignatureDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);
		ASiCParameters asicParameters = parameters.aSiC();
		assertSignaturePossible(asicContent.getTimestampDocuments(), asicParameters);

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);
		cadesParameters.getContext().setDetachedContents(dataToSignHelper.getDetachedContents());

		// Archive Timestamp in case of ASiC-E is not embedded into the CAdES signature
		boolean addASiCArchiveManifest = isAddASiCEArchiveManifest(parameters.getSignatureLevel(), parameters.aSiC().getContainerType());
		if (addASiCArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		DSSDocument toBeSigned = dataToSignHelper.getToBeSigned();
		if (ASiCContainerType.ASiC_E == asicParameters.getContainerType()) {
			asicContent.getManifestDocuments().add(toBeSigned); // XML Document in case of ASiC-E container
		}

		final DSSDocument signature = getCAdESService().signDocument(toBeSigned, cadesParameters, signatureValue);
		signature.setName(asicFilenameFactory.getSignatureFilename(asicContent));

		ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), signature);

		if (addASiCArchiveManifest) {
			final ASiCWithCAdESSignatureExtension extensionProfile = new ASiCWithCAdESLevelBaselineLTA(
					certificateVerifier, tspSource, asicFilenameFactory);
			asicContent = extensionProfile.extend(asicContent, parameters);

			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		final DSSDocument asicContainer = buildASiCContainer(asicContent, parameters.getZipCreationDate());
		asicContainer.setName(getFinalDocumentName(asicContainer, SigningOperation.SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		parameters.reinit();
		return asicContainer;
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, ASiCWithCAdESTimestampParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toTimestampDocuments)) {
			throw new IllegalArgumentException("List of documents to be timestamped cannot be empty!");
		}

		ASiCContent asicContent = new ASiCWithCAdESASiCContentBuilder()
				.build(toTimestampDocuments, parameters.aSiC().getContainerType());

		ASiCParameters asicParameters = parameters.aSiC();
		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();

		assertTimestampPossible(signatureDocuments, asicParameters);

		List<DSSDocument> signatures = asicContent.getSignatureDocuments();
		List<DSSDocument> timestampDocuments = asicContent.getTimestampDocuments();
		if ((Utils.isCollectionNotEmpty(signatures) || Utils.isCollectionNotEmpty(timestampDocuments))
				&& isLtaExtensionPossible(asicContent)) {
			DSSDocument toTimestampDocument = toTimestampDocuments.get(0);

			final ASiCWithCAdESLevelBaselineLTA extensionProfile = new ASiCWithCAdESLevelBaselineLTA(
					certificateVerifier, tspSource, asicFilenameFactory);
			asicContent = extensionProfile.extend(asicContent, parameters.getDigestAlgorithm());

			final DSSDocument extensionResult = buildASiCContainer(asicContent, parameters.getZipCreationDate());
			extensionResult.setName(getFinalDocumentName(
					toTimestampDocument, SigningOperation.TIMESTAMP, null, toTimestampDocument.getMimeType()));
			return extensionResult;

		} else {
			ASiCWithCAdESTimestampService timestampService = new ASiCWithCAdESTimestampService(tspSource, asicFilenameFactory);
			asicContent = timestampService.timestamp(asicContent, parameters);

			final DSSDocument asicContainer = buildASiCContainer(asicContent, parameters.getZipCreationDate());
			asicContainer.setName(getFinalDocumentName(asicContainer, SigningOperation.TIMESTAMP, null, asicContainer.getMimeType()));
			return asicContainer;
		}
	}

	/**
	 * LTA extension is not possible when a signature does not have a signature-time-stamp,
	 * as it will make the further signature extension impossible as per 162-1
	 *
	 * @param asicContent {@link ASiCContent} to verify
	 * @return TRUE if the LTA extension is possible, FALSE otherwise
	 */
	private boolean isLtaExtensionPossible(ASiCContent asicContent) {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator(asicContent);
		validator.setCertificateVerifier(certificateVerifier);

		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			if (Utils.isCollectionEmpty(signature.getSignatureTimestamps())) {
				LOG.warn("Extension with an ArchiveManifest is not possible, because a " +
						"signature with Id '{}' does not have a signature-time-stamp attribute!" +
						"Add a simple timestamp on signed data.", signature.getId());
				return false;
			}
		}
		return true;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithCAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");

		assertExtensionSupported(toExtendDocument);
		ASiCContent asicContent = extractCurrentArchive(toExtendDocument);

		assertValidSignaturesToExtendFound(asicContent.getSignatureDocuments());

		ASiCContainerType containerType = asicContent.getContainerType();
		if (containerType == null) {
			throw new IllegalInputException("The container type of the provided document is not supported or cannot be extracted!");
		}

		CAdESSignatureParameters cadesParameters = getCAdESParameters(parameters);

		boolean addASiCEArchiveManifest = isAddASiCEArchiveManifest(parameters.getSignatureLevel(), containerType);
		final ASiCWithCAdESSignatureExtension extensionProfile = getExtensionProfile(parameters.getSignatureLevel(), containerType);

		if (addASiCEArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
		}

		asicContent = extensionProfile.extend(asicContent, parameters);

		if (addASiCEArchiveManifest) {
			cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		}

		final DSSDocument extensionResult = buildASiCContainer(asicContent, parameters.getZipCreationDate());
		extensionResult.setName(getFinalDocumentName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(),
				toExtendDocument.getMimeType()));
		return extensionResult;
	}

	private void assertExtensionSupported(DSSDocument toExtendDocument) {
		if (!ASiCUtils.isZip(toExtendDocument)) {
			throw new IllegalInputException("Unsupported file type");
		}
	}

	private void assertValidSignaturesToExtendFound(List<DSSDocument> signatureDocuments) {
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new IllegalInputException("No supported signature documents found! Unable to extend the container.");
		}
	}

	@Override
	protected DefaultASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithCAdESContainerExtractor(archive);
	}

	/**
	 * Returns the {@code CAdESService} to be used for signature/timestamp creation
	 *
	 * @return {@link CAdESService}
	 */
	protected CAdESService getCAdESService() {
		CAdESService cadesService = new CAdESService(certificateVerifier);
		cadesService.setTspSource(tspSource);
		return cadesService;
	}

	/**
	 * Returns {@code CAdESSignatureParameters} from the given {@code ASiCWithCAdESSignatureParameters}
	 *
	 * @param parameters {@link ASiCWithCAdESSignatureParameters}
	 * @return {@link CAdESSignatureParameters}
	 */
	protected CAdESSignatureParameters getCAdESParameters(ASiCWithCAdESSignatureParameters parameters) {
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.getContext().setDetachedContents(null);
		return parameters;
	}

	private boolean isAddASiCEArchiveManifest(SignatureLevel signatureLevel, ASiCContainerType containerType) {
		return SignatureLevel.CAdES_BASELINE_LTA == signatureLevel && ASiCContainerType.ASiC_E == containerType;
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the ASiC
	 * with CAdES Signature
	 * 
	 * @param asicContainer        {@link DSSDocument} containing a CAdES Signature
	 *                             to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} ASiC with CAdES container with an incorporated
	 *         SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument asicContainer, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(asicContainer, "The asicContainer cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");

		ASiCContent asicContent = extractCurrentArchive(asicContainer);
		assertAddSignaturePolicyStorePossible(asicContent);

		CAdESService cadesService = getCAdESService();

		final List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		// Ensure iteration not over original list
		Iterator<DSSDocument> iterator = new ArrayList<>(signatureDocuments).iterator();
		while (iterator.hasNext()) {
			DSSDocument signature = iterator.next();
			DSSDocument signatureWithPolicyStore = cadesService.addSignaturePolicyStore(signature, signaturePolicyStore);
			signatureWithPolicyStore.setName(signature.getName());
			ASiCUtils.addOrReplaceDocument(signatureDocuments, signatureWithPolicyStore);
		}

		final DSSDocument resultArchive = buildASiCContainer(asicContent, null);
		resultArchive.setName(getFinalArchiveName(asicContainer, SigningOperation.ADD_SIG_POLICY_STORE, asicContainer.getMimeType()));
		return resultArchive;
	}
	
	@Override
	protected void assertAddSignaturePolicyStorePossible(ASiCContent asicContent) {
		super.assertAddSignaturePolicyStorePossible(asicContent);

		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		for (DSSDocument signature : signatureDocuments) {
			if (ASiCWithCAdESUtils.isCoveredByManifest(asicContent.getAllManifestDocuments(), signature.getName())) {
				throw new IllegalInputException(String.format("Not possible to add a signature policy store! "
						+ "Reason : a signature with a filename '%s' is covered by another manifest.", signature.getName()));
			}
		}
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument asicContainer, CAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSigningCertificateValid(parameters);
		assertCounterSignatureParametersValid(parameters);

		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithCAdESCounterSignatureHelper(asicContainer);
		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());

		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		counterSignatureBuilder.setManifestFile(counterSignatureHelper.getManifestFile(signatureDocument.getName()));
		
		SignerInformation signerInfoToCounterSign = counterSignatureBuilder.getSignerInformationToBeCounterSigned(signatureDocument, parameters);

		CAdESService cadesService = getCAdESService();
		return cadesService.getDataToBeCounterSigned(signerInfoToCounterSign, parameters);
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument asicContainer, CAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		assertCounterSignatureParametersValid(parameters);
		
		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithCAdESCounterSignatureHelper(asicContainer);
		ASiCContent asicContent = counterSignatureHelper.getAsicContent();

		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());
		CMSSignedData originalCMSSignedData = DSSUtils.toCMSSignedData(signatureDocument);
		
		CAdESCounterSignatureBuilder counterSignatureBuilder = new CAdESCounterSignatureBuilder(certificateVerifier);
		counterSignatureBuilder.setManifestFile(counterSignatureHelper.getManifestFile(signatureDocument.getName()));
		
		CMSSignedDocument counterSignedSignature = counterSignatureBuilder.addCounterSignature(originalCMSSignedData, parameters, signatureValue);
		counterSignedSignature.setName(signatureDocument.getName());
		ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), counterSignedSignature);

		final DSSDocument resultArchive = buildASiCContainer(asicContent, parameters.bLevel().getSigningDate());
		resultArchive.setName(getFinalDocumentName(asicContainer, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		return resultArchive;
	}

	/**
	 * Returns the extension profile to be used for the current signature
	 *
	 * @param signatureLevel
	 *            {@link SignatureLevel}
	 * @param containerType
	 * 			  {@link ASiCContainerType}
	 * @return {@code ASiCWithCAdESSignatureExtension} related to the pre-defined profile
	 */
	protected ASiCWithCAdESSignatureExtension getExtensionProfile(final SignatureLevel signatureLevel,
																final ASiCContainerType containerType) {
		Objects.requireNonNull(signatureLevel, "SignatureLevel must be defined!");
		switch (signatureLevel) {
			case CAdES_BASELINE_T:
			case CAdES_BASELINE_LT:
				return new ASiCWithCAdESSignatureExtension(certificateVerifier, tspSource);
			case CAdES_BASELINE_LTA:
				return ASiCContainerType.ASiC_E.equals(containerType) ?
						new ASiCWithCAdESLevelBaselineLTA(certificateVerifier, tspSource, asicFilenameFactory) :
						new ASiCWithCAdESSignatureExtension(certificateVerifier, tspSource);
			default:
				throw new UnsupportedOperationException(
						String.format("Unsupported signature format '%s' for extension.", signatureLevel));
		}
	}

	@Override
	protected void assertCounterSignatureParametersValid(CAdESCounterSignatureParameters parameters) {
		super.assertCounterSignatureParametersValid(parameters);

		if (!SignatureLevel.CAdES_BASELINE_B.equals(parameters.getSignatureLevel())) {
			throw new UnsupportedOperationException(String.format("A counter signature with a level '%s' is not supported! "
					+ "Please, use CAdES-BASELINE-B", parameters.getSignatureLevel()));
		}
	}

	private void assertSignaturePossible(List<DSSDocument> timestampDocuments, ASiCParameters asicParameters) {
		if (ASiCUtils.isASiCS(asicParameters) && Utils.isCollectionNotEmpty(timestampDocuments)) {
			throw new IllegalInputException("Unable to sign an ASiC-S with CAdES container containing time assertion files!");
		}
	}

	private void assertTimestampPossible(List<DSSDocument> signatureDocuments, ASiCParameters asicParameters) {
		if (ASiCUtils.isASiCS(asicParameters) && Utils.isCollectionNotEmpty(signatureDocuments)) {
			throw new IllegalInputException("Unable to timestamp an ASiC-S with CAdES container containing signature files! " +
					"Use extendDocument(...) method for signature extension.");
		}
	}

}
