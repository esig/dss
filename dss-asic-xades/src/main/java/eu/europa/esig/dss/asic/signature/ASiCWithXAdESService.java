package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ASiCWithXAdESService extends AbstractASiCSignatureService<ASiCWithXAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESService.class);

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.NS);
	}

	public ASiCWithXAdESService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
		LOG.debug("+ ASiCService with XAdES created");
	}

	@Override
	public ToBeSigned getDataToSign(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocuments, asicParameters);

		GetDataToSignASiCWithXAdESHelper dataToSignHelper = ASiCWithXAdESDataToSignHelperBuilder.getGetDataToSignHelper(toSignDocuments, parameters);

		XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, dataToSignHelper.getExistingSignature());
		return getXAdESService().getDataToSign(dataToSignHelper.getToBeSigned(), xadesParameters);
	}

	@Override
	public DSSDocument signDocument(List<DSSDocument> toSignDocuments, ASiCWithXAdESSignatureParameters parameters, SignatureValue signatureValue)
			throws DSSException {
		final ASiCParameters asicParameters = parameters.aSiC();
		assertCanBeSign(toSignDocuments, asicParameters);
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
				.setName(DSSUtils.getFinalFileName(asicSignature, SigningOperation.SIGN, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		parameters.reinitDeterministicId();
		return asicSignature;
	}

	@Override
	public DSSDocument extendDocument(DSSDocument toExtendDocument, ASiCWithXAdESSignatureParameters parameters) throws DSSException {
		if (!ASiCUtils.isASiCContainer(toExtendDocument) || !ASiCUtils.isArchiveContainsCorrectSignatureExtension(toExtendDocument, ".xml")) {
			throw new DSSException("Unsupported file type");
		}

		extractCurrentArchive(toExtendDocument);
		List<DSSDocument> signedDocuments = getEmbeddedSignedDocuments();
		List<DSSDocument> signatureDocuments = getEmbeddedSignatures();

		List<DSSDocument> extendedDocuments = new ArrayList<DSSDocument>();

		for (DSSDocument signature : signatureDocuments) {
			XAdESSignatureParameters xadesParameters = getXAdESParameters(parameters, null);
			xadesParameters.setDetachedContents(signedDocuments);
			DSSDocument extendDocument = getXAdESService().extendDocument(signature, xadesParameters);
			extendedDocuments.add(extendDocument);
		}

		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			copyExistingArchiveWithSignatureList(toExtendDocument, extendedDocuments, baos);
		} finally {
			Utils.closeQuietly(baos);
		}

		DSSDocument asicSignature = new InMemoryDocument(baos.toByteArray(), null, toExtendDocument.getMimeType());
		asicSignature.setName(
				DSSUtils.getFinalFileName(toExtendDocument, SigningOperation.EXTEND, parameters.getSignatureLevel(), parameters.aSiC().getContainerType()));
		return asicSignature;
	}

	@Override
	void storeSignatures(List<DSSDocument> signatures, ZipOutputStream zos) throws IOException {
		for (DSSDocument dssDocument : signatures) {
			ZipEntry entrySignature = new ZipEntry(dssDocument.getName());
			zos.putNextEntry(entrySignature);
			Document xmlSignatureDoc = DomUtils.buildDOM(dssDocument);
			DomUtils.writeDocumentTo(xmlSignatureDoc, zos);
		}
	}

	@Override
	boolean isSignatureFilename(String name) {
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
			rootDocument = DomUtils.createDocument(ASiCNamespace.NS, ASiCNamespace.XADES_SIGNATURES);
		}
		xadesParameters.setRootDocument(rootDocument);
		return xadesParameters;
	}

	@Override
	AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive) {
		return new ASiCWithXAdESContainerExtractor(archive);
	}

	@Override
	boolean canBeSigned(List<DSSDocument> documents, ASiCParameters asicParameters) {
		boolean isMimetypeCorrect = true;
		boolean isSignatureTypeCorrect = true;
		if (ASiCUtils.isArchive(documents)) {
			DSSDocument archive = documents.get(0);
			String expectedMimeType = archive.getMimeType().getMimeTypeString();
			String mimeTypeFromParameter = ASiCUtils.getMimeTypeString(asicParameters);
			isMimetypeCorrect = Utils.areStringsEqualIgnoreCase(expectedMimeType, mimeTypeFromParameter);
			if (isMimetypeCorrect) {
				isSignatureTypeCorrect = ASiCUtils.isArchiveContainsCorrectSignatureExtension(archive, ".xml");
			}
		}
		return isMimetypeCorrect && isSignatureTypeCorrect;
	}

}
