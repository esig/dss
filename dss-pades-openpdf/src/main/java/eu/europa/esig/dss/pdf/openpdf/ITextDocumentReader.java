package eu.europa.esig.dss.pdf.openpdf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.AcroFields.Item;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.SingleDssDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public class ITextDocumentReader implements PdfDocumentReader {

	private static final Logger LOG = LoggerFactory.getLogger(ITextDocumentReader.class);
	
	private final PdfReader pdfReader;
	
	private Map<PdfSignatureDictionary, List<String>> signatureDictionaryMap;
	
	public ITextDocumentReader(DSSDocument dssDocument) {
		Objects.requireNonNull(dssDocument, "The document must be defined!");
		try (InputStream is = dssDocument.openStream()) {
			this.pdfReader = new PdfReader(is);
		} catch (IOException e) {
			throw new DSSException(String.format("The document with name [%s] is either not accessible or not PDF compatible. Reason : [%s]", 
					dssDocument.getName(), e.getMessage(), e)); 
		}
	}
	
	public ITextDocumentReader(byte[] binaries) throws IOException {
		Objects.requireNonNull(binaries, "The document binaries must be defined!");
		this.pdfReader = new PdfReader(binaries);
	}

	@Override
	public PdfDssDict getDSSDictionary() {
		PdfDict currentCatalog = new ITextPdfDict(pdfReader.getCatalog());
		return SingleDssDict.extract(currentCatalog);
	}

	@Override
	public Map<PdfSignatureDictionary, List<String>> extractSigDictionaries() {
		if (signatureDictionaryMap == null) {
			AcroFields acroFields = pdfReader.getAcroFields();
			
			Map<PdfSignatureDictionary, List<String>> pdfDictionaries = new LinkedHashMap<>();
			Map<Integer, PdfSigDictWrapper> pdfObjectDictMap = new LinkedHashMap<>();
			
			Map<String, Item> allFields = acroFields.getAllFields();
			List<String> names = acroFields.getSignedFieldNames();
			LOG.info("{} signature field(s) found", names.size());
			
			for (String name : names) {
				PdfDictionary pdfField = allFields.get(name).getMerged(0);
				int refNumber = pdfField.getAsIndirectObject(PdfName.V).getNumber();
				PdfSigDictWrapper signature = pdfObjectDictMap.get(refNumber);
				if (signature == null) {
					PdfDict dictionary = new ITextPdfDict(pdfField.getAsDict(PdfName.V));
					signature = new PdfSigDictWrapper(dictionary);
	
					pdfDictionaries.put(signature, new ArrayList<>(Arrays.asList(name)));
					pdfObjectDictMap.put(refNumber, signature);
					
				} else {
					List<String> fieldNameList = pdfDictionaries.get(signature);
					fieldNameList.add(name);
					LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldNameList);
					
				}
			}
			signatureDictionaryMap = pdfDictionaries;
		}
		return signatureDictionaryMap;
	}

	@Override
	public void close() throws IOException {
		pdfReader.close();
	}

	@Override
	public boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary) {
		AcroFields acroFields = pdfReader.getAcroFields();
		List<String> fieldNames = signatureDictionaryMap.get(signatureDictionary);
		if (Utils.isCollectionNotEmpty(fieldNames)) {
			return acroFields.signatureCoversWholeDocument(fieldNames.get(0));
		}
		throw new DSSException("Not applicable use of the method isSignatureCoversWholeDocument. The requested signatureDictionary does not exist!");
	}

}
