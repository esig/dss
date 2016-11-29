package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;

public abstract class AbstractASiCSignatureService<SP extends AbstractSignatureParameters> extends AbstractSignatureService<SP> {

	private static final long serialVersionUID = 243114076381526665L;

	protected final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";

	private ASiCExtractResult archiveContent = new ASiCExtractResult();

	protected AbstractASiCSignatureService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	protected void assertCanBeSign(DSSDocument toSignDocument, final ASiCParameters asicParameters) {
		if (!canBeSigned(toSignDocument, asicParameters)) { // First verify if the file can be signed
			throw new DSSUnsupportedOperationException("You only can sign an ASiC container by using the same type of container and of signature");
		}
	}

	abstract boolean canBeSigned(DSSDocument toSignDocument, ASiCParameters asicParameters);

	protected void extractCurrentArchive(DSSDocument archive) {
		ASiCContainerExtractor extractor = new ASiCContainerExtractor(archive);
		archiveContent = extractor.extract();
	}

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

	protected void copyZipContent(DSSDocument toSignAsicContainer, ZipOutputStream zos) throws IOException {
		InputStream is = null;
		ZipInputStream zis = null;
		try {
			is = toSignAsicContainer.openStream();
			zis = new ZipInputStream(is);
			ZipEntry entry = null;
			while ((entry = zis.getNextEntry()) != null) {
				zos.putNextEntry(entry);
				Utils.copy(zis, zos);
			}
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(is);
		}
	}

	protected void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream zos) {
		if (asicParameters.isZipComment()) {
			zos.setComment("mimetype=" + ASiCUtils.getMimeTypeString(asicParameters));
		}
	}

	protected String getSignatureNumber(List<DSSDocument> existingSignatures) {
		int signatureNumbre = existingSignatures.size() + 1;
		String sigNumberStr = String.valueOf(signatureNumbre);
		String zeroPad = "000";
		return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

	protected InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream baos) {
		return new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
	}

}
