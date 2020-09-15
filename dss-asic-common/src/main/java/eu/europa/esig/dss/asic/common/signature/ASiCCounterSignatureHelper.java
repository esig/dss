package eu.europa.esig.dss.asic.common.signature;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;

public abstract class ASiCCounterSignatureHelper {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCCounterSignatureHelper.class);
	
	protected final DSSDocument asicContainer;
	
	private ASiCExtractResult extractResult;
	
	protected ASiCCounterSignatureHelper(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	} 
	
	/**
	 * Returns a file containing a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to extract a file with
	 * @return {@link DSSDocument} signature document containing a signature to be counter signed with a defined id
	 */
	public DSSDocument extractSignatureDocument(String signatureId) {		
		if (ASiCUtils.isAsic(asicContainer)) {
			
			List<DSSDocument> signatureDocuments = getSignatureDocuments();
			for (DSSDocument signatureDocument : signatureDocuments) {
				if (containsSignatureToBeCounterSigned(signatureDocument, signatureId)) {
					return signatureDocument;
				}
			}
			
			throw new DSSException(String.format("A signature with id '%s' has not been found!", signatureId));
			
		} else {
			throw new DSSException("The provided file shall be an ASiC container!");
		}
		
	}

	/**
	 * Returns a list if signature documents from the container
	 * 
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		ASiCExtractResult extractResult = getASiCExtractResult();
		return extractResult.getSignatureDocuments();
	}
	
	/**
	 * Returns a list if all documents contained in the container
	 * 
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		ASiCExtractResult extractResult = getASiCExtractResult();
		return extractResult.getAllDocuments();
	}
	
	private ASiCExtractResult getASiCExtractResult() {
		if (extractResult == null) {
			AbstractASiCContainerExtractor extractor = getASiCContainerExtractor();
			extractResult = extractor.extract();
		}
		return extractResult;
	}
	
	/**
	 * Gets an ASiC container extractor relative to the current implementation
	 * 
	 * @return {@link AbstractASiCContainerExtractor}
	 */
	protected abstract AbstractASiCContainerExtractor getASiCContainerExtractor();

	/**
	 * Gets a Document Validator relative to the current implementation
	 * 
	 * @param signatureDocument {@link DSSDocument}
	 * @return {@link DocumentValidator}
	 */
	protected abstract DocumentValidator getDocumentValidator(DSSDocument signatureDocument);
	
	private boolean containsSignatureToBeCounterSigned(DSSDocument signatureDocument, String signatureId) {
		try {
			DocumentValidator validator = getDocumentValidator(signatureDocument);
			List<AdvancedSignature> signatures = validator.getSignatures();
			for (AdvancedSignature signature : signatures) {
				if (containsSignatureToBeCounterSigned(signature, signatureId)) {
					return true;
				}
			}
		} catch (Exception e) {
			String errorMessage = "Unable to verify a file with name '{}'. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, signatureDocument.getName(), e.getMessage());
			}
		}
		return false;
	}
	
	private boolean containsSignatureToBeCounterSigned(AdvancedSignature signature, String signatureId) {
		if (signatureId.equals(signature.getId())) {
			return true;
		}
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			if (containsSignatureToBeCounterSigned(counterSignature, signatureId)) {
				return true;
			}
		}
		return false;
	}

}
