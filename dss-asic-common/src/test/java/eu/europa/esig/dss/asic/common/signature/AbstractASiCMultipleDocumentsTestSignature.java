package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCTestUtils;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestMultipleDocumentsSignatureService;

public abstract class AbstractASiCMultipleDocumentsTestSignature<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters>
		extends AbstractPkiFactoryTestMultipleDocumentsSignatureService<SP, TP> {

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		ASiCTestUtils.verifyZipContainer(new InMemoryDocument(byteArray));
	}

}
