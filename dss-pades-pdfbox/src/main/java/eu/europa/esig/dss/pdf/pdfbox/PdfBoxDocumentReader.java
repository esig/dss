package eu.europa.esig.dss.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.SingleDssDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ByteRange;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public class PdfBoxDocumentReader implements PdfDocumentReader {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxDocumentReader.class);
	
	private DSSDocument dssDocument;
	
	private final PDDocument pdDocument;
	
	public PdfBoxDocumentReader(DSSDocument dssDocument) {
		Objects.requireNonNull(dssDocument, "The document must be defined!");
		this.dssDocument = dssDocument;
		try (InputStream is = dssDocument.openStream()) {
			this.pdDocument = PDDocument.load(is);
		} catch (IOException e) {
			throw new DSSException(String.format("The document with name [%s] is either not accessible or not PDF compatible. Reason : [%s]", 
					dssDocument.getName(), e.getMessage(), e)); 
		}
	}
	
	public PdfBoxDocumentReader(byte[] binaries) throws IOException {
		Objects.requireNonNull(binaries, "The document binaries must be defined!");
		this.pdDocument = PDDocument.load(binaries);
	}

	@Override
	public PdfDssDict getDSSDictionary() {
		PdfDict catalog = new PdfBoxDict(pdDocument.getDocumentCatalog().getCOSObject(), pdDocument);
		return SingleDssDict.extract(catalog);
	}

	@Override
	public Map<PdfSignatureDictionary, List<String>> extractSigDictionaries() throws IOException {
		Map<PdfSignatureDictionary, List<String>> pdfDictionaries = new LinkedHashMap<>();
		Map<Long, PdfSignatureDictionary> pdfObjectDictMap = new LinkedHashMap<>();

		List<PDSignatureField> pdSignatureFields = pdDocument.getSignatureFields();
		if (Utils.isCollectionNotEmpty(pdSignatureFields)) {
			LOG.debug("{} signature(s) found", pdSignatureFields.size());
			
			for (PDSignatureField signatureField : pdSignatureFields) {
				
				String signatureFieldName = signatureField.getPartialName();

				COSObject sigDictObject = signatureField.getCOSObject().getCOSObject(COSName.V);
				if (sigDictObject == null || !(sigDictObject.getObject() instanceof COSDictionary)) {
					LOG.warn("Signature field with name '{}' does not contain a signature", signatureFieldName);
					continue;
				}
				
				long sigDictNumber = sigDictObject.getObjectNumber();
				PdfSignatureDictionary signature = pdfObjectDictMap.get(sigDictNumber);
				if (signature == null) {					
					PdfDict dictionary = new PdfBoxDict((COSDictionary)sigDictObject.getObject(), pdDocument);
					signature = new PdfSigDictWrapper(dictionary);
					
					pdfDictionaries.put(signature, new ArrayList<>(Arrays.asList(signatureFieldName)));
					pdfObjectDictMap.put(sigDictNumber, signature);
					
				} else {
					List<String> fieldNameList = pdfDictionaries.get(signature);
					fieldNameList.add(signatureFieldName);
					LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldNameList);
					
				}
				
			}	
		}
		return pdfDictionaries;
	}

	@Override
	public boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary) {
		ByteRange byteRange = signatureDictionary.getByteRange();
		try (InputStream is = dssDocument.openStream()) {
			long originalBytesLength = Utils.getInputStreamSize(is);
			// /ByteRange [0 575649 632483 10206]
			long beforeSignatureLength = (long)byteRange.getFirstPartEnd() - byteRange.getFirstPartStart();
			long expectedCMSLength = (long)byteRange.getSecondPartStart() - byteRange.getFirstPartEnd() - byteRange.getFirstPartStart();
			long afterSignatureLength = byteRange.getSecondPartEnd();
			long totalCoveredByByteRange = beforeSignatureLength + expectedCMSLength + afterSignatureLength;

			return (originalBytesLength == totalCoveredByByteRange);
		} catch (IOException e) {
			LOG.warn("Cannot determine the original file size for the document. Reason : {}", e.getMessage());
			return false;
		}
	}

	@Override
	public void close() throws IOException {
		pdDocument.close();
	}

}
