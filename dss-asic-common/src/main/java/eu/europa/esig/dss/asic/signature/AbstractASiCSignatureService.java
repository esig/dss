package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public abstract class AbstractASiCSignatureService<SP extends AbstractSignatureParameters> extends AbstractSignatureService<SP>
		implements MultipleDocumentsSignatureService<SP> {

	private static final long serialVersionUID = 243114076381526665L;

	protected final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";

	private ASiCExtractResult archiveContent = new ASiCExtractResult();

	protected AbstractASiCSignatureService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	protected void assertCanBeSign(List<DSSDocument> documents, final ASiCParameters asicParameters) {
		if (!canBeSigned(documents, asicParameters)) { // First verify if the file can be signed
			throw new DSSUnsupportedOperationException("You only can sign an ASiC container by using the same type of container and of signature");
		}
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, SP parameters) throws DSSException {
		return getDataToSign(Arrays.asList(toSignDocument), parameters);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, SP parameters, SignatureValue signatureValue) throws DSSException {
		return signDocument(Arrays.asList(toSignDocument), parameters, signatureValue);
	}

	abstract boolean canBeSigned(List<DSSDocument> documents, ASiCParameters asicParameters);

	protected void extractCurrentArchive(DSSDocument archive) {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor(archive);
		archiveContent = extractor.extract();
	}

	abstract AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive);

	protected List<DSSDocument> getEmbeddedSignatures() {
		return archiveContent.getSignatureDocuments();
	}

	protected List<DSSDocument> getEmbeddedManifests() {
		return archiveContent.getManifestDocuments();
	}

	protected List<DSSDocument> getEmbeddedSignedDocuments() {
		return archiveContent.getSignedDocuments();
	}

	protected DSSDocument getEmbeddedMimetype() {
		return archiveContent.getMimeTypeDocument();
	}

	protected DSSDocument createPackageZip(List<DSSDocument> documents) {
		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);
			storeSignedFiles(documents, zos);
		} catch (IOException e) {
			throw new DSSException("Unable to create package.zip file", e);
		} finally {
			Utils.closeQuietly(zos);
			Utils.closeQuietly(baos);
		}
		return new InMemoryDocument(baos.toByteArray(), "package.zip");
	}

	protected void copyExistingArchiveWithSignatureList(DSSDocument archiveDocument, List<DSSDocument> signaturesToAdd, ByteArrayOutputStream baos) {
		ZipOutputStream zos = null;
		try {
			zos = new ZipOutputStream(baos);
			copyArchiveContentWithoutSignatures(archiveDocument, zos);
			storeSignatures(signaturesToAdd, zos);
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		} finally {
			Utils.closeQuietly(zos);
		}
	}

	private void copyArchiveContentWithoutSignatures(DSSDocument archiveDocument, ZipOutputStream zos) throws IOException {
		ZipInputStream zis = null;
		try {
			zis = new ZipInputStream(archiveDocument.openStream());
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (!isSignatureFilename(name)) {
					zos.putNextEntry(newEntry);
					Utils.copy(zis, zos);
				}
			}
		} finally {
			Utils.closeQuietly(zis);
		}
	}

	abstract boolean isSignatureFilename(String name);

	abstract void storeSignatures(List<DSSDocument> signaturesToAdd, ZipOutputStream zos) throws IOException;

	protected void storeSignedFiles(final List<DSSDocument> detachedDocuments, final ZipOutputStream zos) throws IOException {
		for (DSSDocument detachedDocument : detachedDocuments) {
			InputStream is = null;
			try {
				final String detachedDocumentName = detachedDocument.getName();
				final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				zos.setLevel(ZipEntry.DEFLATED);

				zos.putNextEntry(entryDocument);
				is = detachedDocument.openStream();
				Utils.copy(is, zos);
			} finally {
				Utils.closeQuietly(is);
			}
		}
	}

	protected void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream zos) throws IOException {
		final byte[] mimeTypeBytes = ASiCUtils.getMimeTypeString(asicParameters).getBytes("UTF-8");
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);
		zos.putNextEntry(entryMimetype);
		Utils.write(mimeTypeBytes, zos);
	}

	private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {
		final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
		entryMimetype.setMethod(ZipEntry.STORED);
		entryMimetype.setSize(mimeTypeBytes.length);
		entryMimetype.setCompressedSize(mimeTypeBytes.length);
		final CRC32 crc = new CRC32();
		crc.update(mimeTypeBytes);
		entryMimetype.setCrc(crc.getValue());
		return entryMimetype;
	}

	protected void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream zos) {
		if (asicParameters.isZipComment()) {
			zos.setComment(ASiCUtils.MIME_TYPE_COMMENT + ASiCUtils.getMimeTypeString(asicParameters));
		}
	}

	protected String getSignatureNumber(List<DSSDocument> existingSignatures) {
		int signatureNumbre = existingSignatures.size() + 1;
		String sigNumberStr = String.valueOf(signatureNumbre);
		String zeroPad = "000";
		return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

}
