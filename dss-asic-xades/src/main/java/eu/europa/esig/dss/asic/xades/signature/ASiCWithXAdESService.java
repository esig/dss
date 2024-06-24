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
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.definition.ASiCManifestElement;
import eu.europa.esig.dss.asic.common.definition.ASiCManifestNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The service containing the main methods for ASiC with XAdES signature creation/extension
 */
@SuppressWarnings("serial")
public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters, 
					XAdESCounterSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	/**
	 * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
	 */
	private ASiCWithXAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithXAdESFilenameFactory();

	static {
		DomUtils.registerNamespace(ASiCManifestNamespace.NS);
		DomUtils.registerNamespace(ManifestNamespace.NS);
	}

	/**
	 * The default constructor to instantiate the service
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to use
	 */
	public ASiCWithXAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with XAdES created");
	}

	/**
	 * Sets {@code ASiCWithXAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
	 * such as signature files.
	 *
	 * @param asicFilenameFactory {@link ASiCWithXAdESFilenameFactory}
	 */
	public void setAsicFilenameFactory(ASiCWithXAdESFilenameFactory asicFilenameFactory) {
		Objects.requireNonNull(asicFilenameFactory, "ASiCWithXAdESFilenameFactory cannot be null!");
		this.asicFilenameFactory = asicFilenameFactory;
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSignaturePossible(toSignDocuments);

		ASiCContent asicContent = new ASiCWithXAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithXAdESHelper getDataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);
		XAdESSignatureParameters xadesParameters = getXAdESParameters(
				parameters, asicContent.getSignatureDocuments(), getDataToSignHelper.isOpenDocument());
		return getXAdESService().getContentTimestamp(getDataToSignHelper.getToBeSigned(), xadesParameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertSignaturePossible(toSignDocuments);
		assertSigningCertificateValid(parameters);

		ASiCContent asicContent = new ASiCWithXAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithXAdESHelper dataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);
		XAdESSignatureParameters xadesParameters = getXAdESParameters(
				parameters, asicContent.getSignatureDocuments(), dataToSignHelper.isOpenDocument());
		return getXAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), xadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		assertSignaturePossible(toSignDocuments);
		assertSigningCertificateValid(parameters);

		ASiCContent asicContent = new ASiCWithXAdESASiCContentBuilder()
				.build(toSignDocuments, parameters.aSiC().getContainerType());
		GetDataToSignASiCWithXAdESHelper dataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder(asicFilenameFactory)
				.build(asicContent, parameters);

		XAdESSignatureParameters xadesParameters = getXAdESParameters(
				parameters, asicContent.getSignatureDocuments(), dataToSignHelper.isOpenDocument());
		final DSSDocument newSignature = getXAdESService().signDocument(dataToSignHelper.getToBeSigned(), xadesParameters, signatureValue);
		newSignature.setName(asicFilenameFactory.getSignatureFilename(asicContent));

		ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), newSignature);

		final DSSDocument asicSignature = buildASiCContainer(asicContent, parameters.bLevel().getSigningDate());
		asicSignature.setName(getFinalDocumentName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), asicSignature.getMimeType()));
		parameters.reinit();
		return asicSignature;
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, XAdESTimestampParameters parameters) {
		throw new UnsupportedOperationException("Timestamp file cannot be added with ASiC-S/E + XAdES");
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");

		assertExtensionSupported(toExtendDocument);
		ASiCContent asicContent = extractCurrentArchive(toExtendDocument);

		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		assertValidSignaturesToExtendFound(signatureDocuments);

		boolean openDocument = ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument());
		List<DSSDocument> detachedContents = getDetachedContents(asicContent, openDocument);

		for (DSSDocument signature : signatureDocuments) {
			XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, Collections.emptyList(), openDocument);
			xadesParameters.setDetachedContents(detachedContents);

			DSSDocument extendedDocument = getXAdESService().extendDocument(signature, xadesParameters);
			extendedDocument.setName(signature.getName());
			ASiCUtils.addOrReplaceDocument(signatureDocuments, extendedDocument);
		}
		final DSSDocument extensionResult = buildASiCContainer(asicContent, parameters.bLevel().getSigningDate());
		extensionResult.setName(getFinalDocumentName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), toExtendDocument.getMimeType()));
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

	/**
	 * This method returns a detached contents to be used for a signature validation
	 *
	 * @param asicContent {@link ASiCContent} representing the extracted ASiC container
	 * @param isOpenDocument defining whether the current container represents an OpenDocument
	 * @return a list of {@link DSSDocument}s
	 */
	protected List<DSSDocument> getDetachedContents(ASiCContent asicContent, boolean isOpenDocument) {
		if (isOpenDocument) {
			return OpenDocumentSupportUtils.getOpenDocumentCoverage(asicContent);
		} else {
			return asicContent.getSignedDocuments();
		}
	}

	/**
	 * Returns the {@code XAdESService} to be used for signing
	 *
	 * @return {@link XAdESService}
	 */
	protected XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(tspSource);
		return xadesService;
	}

	/**
	 * Returns an instance of {@link XAdESSignatureParameters} to be used for a signature file creation
	 *
	 * @param parameters {@link ASiCWithXAdESSignatureParameters}
	 * @param signatureDocuments a list of {@link DSSDocument}s
	 * @param openDocument defining whether the current container represents an OpenDocument
	 * @return {@link XAdESSignatureParameters}
	 */
	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters,
														List<DSSDocument> signatureDocuments, boolean openDocument) {
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

		Document rootDocument;
		// If already existing signature file and ASiC-S OR OpenDocument type, we re-use the same signature file
		if (Utils.isCollectionNotEmpty(signatureDocuments) &&
				(ASiCContainerType.ASiC_S.equals(parameters.aSiC().getContainerType()) || openDocument)) {
			if (Utils.collectionSize(signatureDocuments) > 1) {
				throw new IllegalInputException("Unable to choose signature file to add a new signature into! " +
						"Only one signature file shall be present for the particular container format.");
			}
			DSSDocument existingXAdESSignature = signatureDocuments.iterator().next();
			if (!DomUtils.isDOM(existingXAdESSignature)) {
				throw new IllegalInputException(String.format("The provided signature file '%s' is not a valid XML! " +
						"Unable to sign.", existingXAdESSignature.getName()));
			}
			rootDocument = DomUtils.buildDOM(existingXAdESSignature);

		} else {
			// No signatures or ASiC-E
			rootDocument = buildDomRoot(openDocument);
		}

		parameters.setRootDocument(rootDocument);
		return parameters;
	}

	private Document buildDomRoot(boolean openDocument) {
		Document rootDocument = DomUtils.buildDOM();
		Element xadesSignatures;
		if (openDocument) {
			xadesSignatures = rootDocument.createElementNS(ASiCManifestNamespace.LIBREOFFICE_NS, ASiCManifestNamespace.LIBREOFFICE_SIGNATURES);
		} else {
			xadesSignatures = DomUtils.createElementNS(rootDocument, ASiCManifestNamespace.NS, ASiCManifestElement.XADES_SIGNATURES);
		}
		rootDocument.appendChild(xadesSignatures);
		return rootDocument;
	}

	@Override
	protected DefaultASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithXAdESContainerExtractor(archive);
	}

	/**
	 * Incorporates a Signature Policy Store as an unsigned property into the ASiC
	 * with XAdES Signature
	 * 
	 * @param asicContainer        {@link DSSDocument} containing a XAdES Signature
	 *                             to add a SignaturePolicyStore to
	 * @param signaturePolicyStore {@link SignaturePolicyStore} to add
	 * @return {@link DSSDocument} ASiC with XAdES container with an incorporated
	 *         SignaturePolicyStore
	 */
	public DSSDocument addSignaturePolicyStore(DSSDocument asicContainer, SignaturePolicyStore signaturePolicyStore) {
		Objects.requireNonNull(asicContainer, "The asicContainer cannot be null");
		Objects.requireNonNull(signaturePolicyStore, "The signaturePolicyStore cannot be null");

		ASiCContent asicContent = extractCurrentArchive(asicContainer);
		assertAddSignaturePolicyStorePossible(asicContent);

		XAdESService xadesService = getXAdESService();

		List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
		for (DSSDocument signature : signatureDocuments) {
			DSSDocument signatureWithPolicyStore = xadesService.addSignaturePolicyStore(signature, signaturePolicyStore);
			signatureWithPolicyStore.setName(signature.getName());
			ASiCUtils.addOrReplaceDocument(signatureDocuments, signatureWithPolicyStore);
		}

		final DSSDocument resultArchive = buildASiCContainer(asicContent, null);
		resultArchive.setName(getFinalArchiveName(asicContainer, SigningOperation.ADD_SIG_POLICY_STORE, asicContainer.getMimeType()));
		return resultArchive;
	}

	@Override
	public ToBeSigned getDataToBeCounterSigned(DSSDocument asicContainer, XAdESCounterSignatureParameters parameters) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		assertCounterSignatureParametersValid(parameters);
		
		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithXAdESCounterSignatureHelper(asicContainer);
		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());
		
		XAdESService xadesService = getXAdESService();
		return xadesService.getDataToBeCounterSigned(signatureDocument, parameters);
	}

	@Override
	public DSSDocument counterSignSignature(DSSDocument asicContainer, XAdESCounterSignatureParameters parameters,
			SignatureValue signatureValue) {
		Objects.requireNonNull(asicContainer, "asicContainer cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "signatureValue cannot be null!");
		assertCounterSignatureParametersValid(parameters);
		
		ASiCCounterSignatureHelper counterSignatureHelper = new ASiCWithXAdESCounterSignatureHelper(asicContainer);
		ASiCContent asicContent = counterSignatureHelper.getAsicContent();

		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());
		
		XAdESService xadesService = getXAdESService();
		DSSDocument counterSignedSignature = xadesService.counterSignSignature(signatureDocument, parameters, signatureValue);
		counterSignedSignature.setName(signatureDocument.getName());
		ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), counterSignedSignature);

		final DSSDocument resultArchive = buildASiCContainer(asicContent, parameters.bLevel().getSigningDate());
		resultArchive.setName(getFinalDocumentName(asicContainer, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		return resultArchive;
	}

}
