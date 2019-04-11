package eu.europa.esig.dss.pades;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.utils.Utils;

public final class PAdESUtils {
	
	public static InMemoryDocument getOriginalPDF(PAdESSignature padesSignature) {
		CAdESSignature cadesSignature = padesSignature.getCAdESSignature();
		List<DSSDocument> cadesDetachedFile = cadesSignature.getDetachedContents();
		if (Utils.collectionSize(cadesDetachedFile) == 1) {
			// data before adding the signature value
			DSSDocument dataToBeSigned = cadesDetachedFile.get(0);
			int[] signatureByteRange = padesSignature.getSignatureByteRange();
			DSSDocument firstByteRangePart = DSSUtils.splitDocument(dataToBeSigned, signatureByteRange[0], signatureByteRange[1]);
			InMemoryDocument lastRevision = retrieveLastPDFRevision(firstByteRangePart);
			return lastRevision;
		}
		return null;
	}

	private static InMemoryDocument retrieveLastPDFRevision(DSSDocument firstByteRangePart) {
		final byte[] eof = new byte[] { '%', '%', 'E', 'O', 'F' };
		try (InputStream is = firstByteRangePart.openStream();
				BufferedInputStream bis = new BufferedInputStream(is);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

			ByteArrayOutputStream tempLine = new ByteArrayOutputStream();
			ByteArrayOutputStream tempRevision = new ByteArrayOutputStream();
			int b;
			while ((b = bis.read()) != -1) {
				final char c = (char) b;
				/*
				 * 0x0a = New Line
				 * 0x0d = Carriage return
				 */
				if ((c != 0x0a) && (c != 0x0d)) {
					tempLine.write(b);
				} else {
					final byte[] byteArray = tempLine.toByteArray();
					tempRevision.write(byteArray);
					tempRevision.write(b);
					// End of a document revision
					if (Arrays.equals(byteArray, eof)) {
						baos.write(tempRevision.toByteArray());
						tempRevision.close();
						tempRevision = new ByteArrayOutputStream();
					}
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
				}
			}
			tempRevision.close();
			tempLine.close();

			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), "original.pdf", MimeType.PDF);

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);
		}
	}

}
