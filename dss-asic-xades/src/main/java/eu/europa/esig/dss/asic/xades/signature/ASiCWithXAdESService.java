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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCNamespace;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCSignatureService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.ManifestNamespace;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
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
		DomUtils.registerNamespace("asic", ASiCNamespace.NS);
		DomUtils.registerNamespace("manifest", ManifestNamespace.NS);
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
		GetDataToSignASiCWithXAdESHelper dataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);
		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, dataToSignHelper.getExistingSignature());
		return getXAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), xadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue) {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertSigningDateInCertificateValidityRange(parameters);

		GetDataToSignASiCWithXAdESHelper dataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		List<DSSDocument> signatures = dataToSignHelper.getSignatures();
		List<DSSDocument> manifestFiles = dataToSignHelper.getManifestFiles();
		List<DSSDocument> signedDocuments = dataToSignHelper.getSignedDocuments();

		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, dataToSignHelper.getExistingSignature());
		final DSSDocument newSignature = getXAdESService().signDocument(dataToSignHelper.getToBeSigned(), xadesParameters, signatureValue);
		String newSignatureFilename = dataToSignHelper.getSignatureFilename();
		newSignature.setName(newSignatureFilename);

		if (ASiCUtils.isASiCS(asicParameters)) {
			Iterator<DSSDocument> iterator = signatures.iterator();
			while (iterator.hasNext()) {
				if (Utils.areStringsEqual(newSignatureFilename, iterator.next().getName())) {
					iterator.remove(); // remove existing file to be replaced
				}
			}
		}
		signatures.add(newSignature);

		final DSSDocument asicSignature = buildASiCContainer(signedDocuments, signatures, manifestFiles, asicParameters);
		asicSignature
				.setName(getFinalFileName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) {
		if (!ASiCUtils.isASiCContainer(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureFileWithExtension(toExtendDocument, ".xml")) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		for (DSSDocument signature : signatureDocuments) {
			XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, null);
			if (ASiCUtils.isOpenDocument(getEmbeddedMimetype())) {
				xadesParameters.setDetachedContents(OpenDocumentSupportUtils.getOpenDocumentCoverage(archiveContent));
			} else {
				xadesParameters.setDetachedContents(getEmbeddedSignedDocuments());
			}
			DSSDocument extendDocument = getXAdESService().extendDocument(signature, xadesParameters);
			extendDocument.setName(signature.getName());
			extendedDocuments.add(extendDocument);
		}

		DSSDocument extensionResult = mergeArchiveAndExtendedSignatures(toExtendDocument, extendedDocuments);
		extensionResult.setName(
				getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
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

	private XAdESSignatureParameters getXAdESParameters(ASiCWithXAdESSignatureParameters parameters, DSSDocument existingXAdESSignatureASiCS) {
		XAdESSignatureParameters xadesParameters = parameters;
		xadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		Document rootDocument = null;
		// If ASiC-S + already existing signature file, we re-use the same signature file
		if (existingXAdESSignatureASiCS != null) {
			rootDocument = DomUtils.buildDOM(existingXAdESSignatureASiCS);
		} else {
			rootDocument = DomUtils.buildDOM();
			final Element xadesSignatures = rootDocument.createElementNS(ASiCNamespace.NS, ASiCNamespace.XADES_SIGNATURES);
			rootDocument.appendChild(xadesSignatures);
		}
		xadesParameters.setRootDocument(rootDocument);
		return xadesParameters;
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
