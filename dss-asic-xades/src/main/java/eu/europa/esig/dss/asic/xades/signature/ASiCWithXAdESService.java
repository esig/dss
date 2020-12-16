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

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.definition.ASiCElement;
import eu.europa.esig.dss.asic.common.definition.ASiCNamespace;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * The service containing the main methods for ASiC with XAdES signature creation/extension
 */
@SuppressWarnings("serial")
public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters, 
					XAdESCounterSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	static {
		DomUtils.registerNamespace(ASiCNamespace.NS);
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

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		GetDataToSignASiCWithXAdESHelper getDataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder()
				.build(toSignDocuments, parameters);
		XAdESSignatureParameters xadesParameters = getParameters(parameters, getDataToSignHelper);
		return getXAdESService().getContentTimestamp(getDataToSignHelper.getSignedDocuments(), xadesParameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("List of documents to sign cannot be empty!");
		}
		GetDataToSignASiCWithXAdESHelper dataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder()
				.build(toSignDocuments, parameters);
		XAdESSignatureParameters xadesParameters = getParameters(parameters, dataToSignHelper);
		return getXAdESService().getDataToSign(dataToSignHelper.getSignedDocuments(), xadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocuments, "toSignDocument cannot be null!");
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("List of documents to sign cannot be empty!");
		}

		final ASiCParameters asicParameters = parameters.aSiC();
		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithXAdESHelper dataToSignHelper = new ASiCWithXAdESDataToSignHelperBuilder()
				.build(toSignDocuments, parameters);

		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifestFiles = dataToSignHelper.getManifestFiles();
		List<DSSDocument> signedDocuments = dataToSignHelper.getSignedDocuments();

		DSSDocument rootContainer = dataToSignHelper.getRootDocument();

		XAdESSignatureParameters xadesParameters = getParameters(parameters, dataToSignHelper);
		final DSSDocument newSignature = getXAdESService().signDocument(signedDocuments, xadesParameters, signatureValue);
		String newSignatureFilename = dataToSignHelper.getSignatureFilename();
		newSignature.setName(newSignatureFilename);

		if (ASiCUtils.isASiCS(asicParameters) || rootContainer != null) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFilename, iterator.next().getName())) {
					iterator.remove(); // remove existing file to be replaced
				}
			}
		}

		signatures.add(newSignature);

		final DSSDocument asicSignature;
		if (rootContainer != null) {
			asicSignature = mergeArchiveAndExtendedSignatures(rootContainer, signatures,
					parameters.bLevel().getSigningDate(),
					ASiCUtils.getZipComment(asicParameters));
		} else {
			asicSignature = buildASiCContainer(signedDocuments, signatures, manifestFiles, asicParameters,
					parameters.bLevel().getSigningDate());
		}
		asicSignature.setName(getFinalDocumentName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), asicSignature.getMimeType()));
		parameters.reinitDeterministicId();
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
		extractCurrentArchive(toExtendDocument);
		
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		assertValidSignaturesToExtendFound(signatureDocuments);

		List<DSSDocument> extendedDocuments = new ArrayList<>();

		boolean openDocument = ASiCUtils.isOpenDocument(getEmbeddedMimetype());

		for (DSSDocument signature : signatureDocuments) {

			XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, null, openDocument);
			if (openDocument) {
				xadesParameters.setDetachedContents(OpenDocumentSupportUtils.getOpenDocumentCoverage(archiveContent));
			} else {
				xadesParameters.setDetachedContents(getEmbeddedSignedDocuments());
			}
			DSSDocument extendDocument = getXAdESService().extendDocument(signature, xadesParameters);
			extendDocument.setName(signature.getName());
			extendedDocuments.add(extendDocument);
		}
		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments,
				parameters.bLevel().getSigningDate(),
				ASiCUtils.getZipComment(parameters.aSiC()));
		extensionResult.setName(getFinalDocumentName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), toExtendDocument.getMimeType()));
		return extensionResult;
	}

	private void assertExtensionSupported(DSSDocument toExtendDocument) {
		if (!ASiCUtils.isZip(toExtendDocument)) {
			throw new DSSException("Unsupported file type");
		}
	}

	private void assertValidSignaturesToExtendFound(List<DSSDocument> signatureDocuments) {
		if (Utils.isCollectionEmpty(signatureDocuments)) {
			throw new DSSException("No supported signature documents found! Unable to extend the container.");
		}
	}

	private XAdESService getXAdESService() {
		XAdESService xadesService = new XAdESService(certificateVerifier);
		xadesService.setTspSource(tspSource);
		return xadesService;
	}

	private XAdESSignatureParameters getParameters(ASiCWithXAdESSignatureParameters parameters, GetDataToSignASiCWithXAdESHelper dataToSignHelper) {
		boolean openDocument = dataToSignHelper.getRootDocument() != null;
		return getXAdESParameters(parameters, dataToSignHelper.getExistingSignature(), openDocument);
	}

	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters, DSSDocument existingXAdESSignature, boolean openDocument) {
		XAdESSignatureParameters xadesParameters = parameters;
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		Document rootDocument = null;
		// If ASiC-S OR OpenDocument + already existing signature file, we re-use the same signature file
		if (existingXAdESSignature != null) {
			rootDocument = DomUtils.buildDOM(existingXAdESSignature);
		} else {
			rootDocument = buildDomRoot(openDocument);
		}
		xadesParameters.setRootDocument(rootDocument);
		return xadesParameters;
	}

	private Document buildDomRoot(boolean openDocument) {
		Document rootDocument = DomUtils.buildDOM();
		Element xadesSignatures = null;
		if (openDocument) {
			xadesSignatures = rootDocument.createElementNS(ASiCNamespace.LIBREOFFICE_NS, ASiCNamespace.LIBREOFFICE_SIGNATURES);
		} else {
			xadesSignatures = DomUtils.createElementNS(rootDocument, ASiCNamespace.NS, ASiCElement.XADES_SIGNATURES);
		}
		rootDocument.appendChild(xadesSignatures);
		return rootDocument;
	}

	@Override
	protected AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithXAdESContainerExtractor(archive);
	}

	@Override
	protected String getExpectedSignatureExtension() {
		return ".xml";
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

		extractCurrentArchive(asicContainer);
		assertAddSignaturePolicyStorePossible();

		XAdESService xadesService = getXAdESService();
		List<DSSDocument> extendedSignatures = new ArrayList<>();
		for (DSSDocument signature : getEmbeddedSignatures()) {
			DSSDocument signatureWithPolicyStore = xadesService.addSignaturePolicyStore(signature, signaturePolicyStore);
			signatureWithPolicyStore.setName(signature.getName());
			extendedSignatures.add(signatureWithPolicyStore);
		}

		DSSDocument resultArchive = mergeArchiveAndExtendedSignatures(asicContainer, extendedSignatures, null,
				ASiCUtils.getZipComment(asicContainer.getMimeType().getMimeTypeString()));
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
		DSSDocument signatureDocument = counterSignatureHelper.extractSignatureDocument(parameters.getSignatureIdToCounterSign());
		
		XAdESService xadesService = getXAdESService();
		DSSDocument counterSignedSignature = xadesService.counterSignSignature(signatureDocument, parameters, signatureValue);
		counterSignedSignature.setName(signatureDocument.getName());
		
		List<DSSDocument> newSignaturesList = counterSignatureHelper.getUpdatedSignatureDocumentsList(counterSignedSignature);
		
		DSSDocument resultArchive = mergeArchiveAndExtendedSignatures(asicContainer, newSignaturesList,
				parameters.bLevel().getSigningDate(),
				ASiCUtils.getZipComment(asicContainer.getMimeType().getMimeTypeString()));
		resultArchive.setName(getFinalDocumentName(asicContainer, SigningOperation.COUNTER_SIGN, parameters.getSignatureLevel(), asicContainer.getMimeType()));
		return resultArchive;
	}

}
