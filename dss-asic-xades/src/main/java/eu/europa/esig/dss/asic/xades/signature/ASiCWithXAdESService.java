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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.definition.ASiCElement;
import eu.europa.esig.dss.asic.common.definition.ASiCNamespace;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@SuppressWarnings("serial")
public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	static {
		DomUtils.registerNamespace(ASiCNamespace.NS);
		DomUtils.registerNamespace(ManifestNamespace.NS);
	}

	public ASiCWithXAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with XAdES created");
	}

	@Override
	public TimestampToken getContentTimestamp(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		GetDataToSignASiCWithXAdESHelper getDataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
		return getXAdESService().getContentTimestamp(getDataToSignHelper.getSignedDocuments(), parameters);
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(parameters, "SignatureParameters cannot be null!");
		if (Utils.isCollectionEmpty(toSignDocuments)) {
			throw new DSSException("List of documents to sign cannot be empty!");
		}
		GetDataToSignASiCWithXAdESHelper dataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
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

		GetDataToSignASiCWithXAdESHelper dataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

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

		final DSSDocument asicSignature = buildASiCContainer(signedDocuments, signatures, manifestFiles, asicParameters, rootContainer);
		asicSignature.setName(getFinalArchiveName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), asicSignature.getMimeType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument timestamp(List<DSSDocument> toTimestampDocuments, ASiCWithXAdESSignatureParameters parameters) {
		throw new UnsupportedOperationException("Timestamp file cannot be added with ASiC-S/E + XAdES");
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) {
		Objects.requireNonNull(toExtendDocument, "toExtendDocument is not defined!");
		Objects.requireNonNull(parameters, "Cannot extend the signature. SignatureParameters are not defined!");

		if (!ASiCUtils.isZip(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(toExtendDocument, ".xml")) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();
		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

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
		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments);
		extensionResult.setName(getFinalArchiveName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), toExtendDocument.getMimeType()));
		return extensionResult;
	}

	@Override
	protected boolean isSignatureFilename(String name) {
		return ASiCUtils.isXAdES(name);
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

}
