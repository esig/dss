package eu.europa.esig.dss.jades.validation;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.validation.scope.JAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractJWSDocumentValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractJWSDocumentValidator.class);
	
	protected AbstractJWSDocumentValidator() {
	}

	protected AbstractJWSDocumentValidator(DSSDocument document) {
		super(new JAdESSignatureScopeFinder());
		this.document = document;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		Objects.requireNonNull(signatureId, "Signature Id cannot be null");
		
		List<AdvancedSignature> signatures = getSignatures();
		JAdESSignature signatureById = getSignatureById(signatures, signatureId);
		if (signatureById == null) {
			LOG.warn("Signature with id {} not found", signatureId);
			return Collections.emptyList();
		}
		return signatureById.getOriginalDocuments();
	}
	
	private JAdESSignature getSignatureById(List<AdvancedSignature> signatures, String signatureId) {
		for (AdvancedSignature signature : signatures) {
			if (signatureId.equals(signature.getId())) {
				return (JAdESSignature) signature;
			}
			List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
			if (Utils.isCollectionNotEmpty(counterSignatures)) {
				JAdESSignature counterSignature = getSignatureById(counterSignatures, signatureId);
				if (counterSignature != null) {
					return counterSignature;
				}
			}
		}
		return null;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		final JAdESSignature jadesSignature = (JAdESSignature) advancedSignature;
		try {
			return jadesSignature.getOriginalDocuments();
		} catch (DSSException e) {
			LOG.error("Cannot retrieve a list of original documents");
			return Collections.emptyList();
		}
	}

}
