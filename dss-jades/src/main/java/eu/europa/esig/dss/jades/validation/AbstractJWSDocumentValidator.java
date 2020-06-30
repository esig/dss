package eu.europa.esig.dss.jades.validation;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jades.validation.scope.JAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
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
		for (AdvancedSignature signature : getSignatures()) {
			final JAdESSignature jadesSignature = (JAdESSignature) signature;
			if (signatureId.equals(jadesSignature.getId())) {
				return jadesSignature.getOriginalDocuments();
			}
		}
		return Collections.emptyList();
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
