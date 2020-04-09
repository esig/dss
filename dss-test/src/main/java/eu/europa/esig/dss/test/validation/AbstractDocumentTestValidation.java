package eu.europa.esig.dss.test.validation;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;

public abstract class AbstractDocumentTestValidation<SP extends SerializableSignatureParameters, 
				TP extends SerializableTimestampParameters> extends AbstractPkiFactoryTestValidation<SP, TP> {
	
	protected abstract DSSDocument getSignedDocument();

	@Test
	public void validate() {
		DSSDocument signedDocument = getSignedDocument();
		verify(signedDocument);
	}
	
	@Override
	protected String getSigningAlias() {
		return null;
	}

}
