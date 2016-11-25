package eu.europa.esig.dss.asic.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.ASiCUtils;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractASiCSignatureService<SP extends AbstractSignatureParameters> extends AbstractSignatureService<SP> {

	private static final long serialVersionUID = 243114076381526665L;

	protected final static String META_INF = "META-INF/";
	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";
	private final static String ZIP_ENTRY_MIMETYPE = "mimetype";

	protected AbstractASiCSignatureService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	protected void assertCanBeSign(DSSDocument toSignDocument, final ASiCParameters asicParameters) {
		if (!canBeSigned(toSignDocument, asicParameters)) { // First verify if the file can be signed
			throw new DSSUnsupportedOperationException("You only can sign an ASiC container by using the same type of container and of signature");
		}
	}

	abstract boolean canBeSigned(DSSDocument toSignDocument, ASiCParameters asicParameters);

	protected void storeSignedFiles(final DSSDocument detachedDocument, final ZipOutputStream outZip) throws IOException {
		DSSDocument currentDetachedDocument = detachedDocument;
		do {
			InputStream is = null;
			try {
				final String detachedDocumentName = currentDetachedDocument.getName();
				final String name = detachedDocumentName != null ? detachedDocumentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				outZip.setLevel(ZipEntry.DEFLATED);

				outZip.putNextEntry(entryDocument);
				is = currentDetachedDocument.openStream();
				Utils.copy(is, outZip);
			} finally {
				Utils.closeQuietly(is);
			}
			currentDetachedDocument = currentDetachedDocument.getNextDocument();
		} while (currentDetachedDocument != null);
	}

	protected DSSDocument getDetachedContents(final DocumentValidator subordinatedValidator, DSSDocument originalDocument) {
		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		if ((detachedContents == null) || (detachedContents.size() == 0)) {

			final List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
			DSSDocument currentDocument = originalDocument;
			do {
				detachedContentsList.add(currentDocument);
				subordinatedValidator.setDetachedContents(detachedContentsList);
				currentDocument = currentDocument.getNextDocument();
			} while (currentDocument != null);
		} else {
			originalDocument = null;
			DSSDocument lastDocument = null;
			for (final DSSDocument currentDocument : detachedContents) {
				if (ASiCUtils.isASiCManifestWithCAdES(currentDocument.getName())) {
					originalDocument = currentDocument;
					lastDocument = currentDocument;
				}
			}
			if (originalDocument != null) {
				detachedContents.remove(originalDocument);
			}
			for (final DSSDocument currentDocument : detachedContents) {
				if (originalDocument == null) {
					originalDocument = currentDocument;
				} else {
					lastDocument.setNextDocument(currentDocument);
				}
				lastDocument = currentDocument;
			}

		}
		return originalDocument;
	}

	protected DSSDocument copyDetachedContent(final AbstractSignatureParameters parameters, final DocumentValidator subordinatedValidator) {
		DSSDocument contextToSignDocument = null;
		DSSDocument currentDetachedDocument = null;
		final List<DSSDocument> detachedContents = subordinatedValidator.getDetachedContents();
		for (final DSSDocument detachedDocument : detachedContents) {
			if (contextToSignDocument == null) {
				contextToSignDocument = detachedDocument;
			} else {
				currentDetachedDocument.setNextDocument(detachedDocument);
			}
			currentDetachedDocument = detachedDocument;
		}
		parameters.setDetachedContent(contextToSignDocument);
		return contextToSignDocument;
	}

	protected void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream outZip) throws IOException {
		final byte[] mimeTypeBytes = ASiCUtils.getMimeTypeString(asicParameters).getBytes("UTF-8");
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);
		outZip.putNextEntry(entryMimetype);
		Utils.write(mimeTypeBytes, outZip);
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

	protected void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream zos, final String toSignDocumentName) {
		if (asicParameters.isZipComment() && Utils.isStringNotEmpty(toSignDocumentName)) {
			zos.setComment("mimetype=" + ASiCUtils.getMimeTypeString(asicParameters));
		}
	}

	protected String getSignatureNumber(DSSDocument enclosedSignature) {
		int signatureNumbre = 0;
		while (enclosedSignature != null) {
			signatureNumbre++;
			enclosedSignature = enclosedSignature.getNextDocument();
		}
		String sigNumberStr = String.valueOf(signatureNumbre);
		String zeroPad = "000";
		return zeroPad.substring(sigNumberStr.length()) + sigNumberStr; // 2 -> 002
	}

	protected InMemoryDocument createASiCContainer(final ASiCParameters asicParameters, final ByteArrayOutputStream baos) {
		return new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
	}

	protected DocumentValidator getAsicValidator(final DSSDocument toSignDocument) {
		if (ASiCUtils.isASiCContainer(toSignDocument)) {
			return SignedDocumentValidator.fromDocument(toSignDocument);
		}
		return null;
	}

}
