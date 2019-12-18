package eu.europa.esig.dss.pades;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public final class PAdESUtils {
	
	/**
	 * Returns original signed content for the {@code padesSignature}
	 * @param padesSignature {@link PAdESSignature}
	 * @return {@link InMemoryDocument}
	 */
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
				
				tempLine.write(b);
				byte[] stringBytes = tempLine.toByteArray();
				
				if (Arrays.equals(stringBytes, eof)) {
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
					
					tempRevision.write(stringBytes);
					int c = bis.read();
					// if \n
					if (c == 0x0a) {
						tempRevision.write(c);
					} 
					// if \r
					else if (c == 0x0d) {
						int d = bis.read();
						// if \r\n
						if (d == 0x0a) {
							tempRevision.write(c);
							tempRevision.write(d);
						} else {
							tempLine.write(c);
							tempLine.write(d);
						}
					} else {
						tempLine.write(c);
					}
					baos.write(tempRevision.toByteArray());
					tempRevision.close();
					tempRevision = new ByteArrayOutputStream();
				} else if (b == 0x0a || stringBytes.length > eof.length) {
					tempRevision.write(tempLine.toByteArray());
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
				}
				
			}
			tempLine.close();
			tempRevision.close();

			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), "original.pdf", MimeType.PDF);

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);
		}
	}

}
