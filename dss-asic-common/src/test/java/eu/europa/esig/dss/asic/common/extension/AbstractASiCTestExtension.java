package eu.europa.esig.dss.asic.common.extension;

import eu.europa.esig.dss.asic.common.ASiCTestUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;

public abstract class AbstractASiCTestExtension<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters>
		extends AbstractTestExtension<SP, TP> {

	@Override
	protected void onDocumentSigned(DSSDocument signedDocument) {
		super.onDocumentSigned(signedDocument);
		ASiCTestUtils.verifyZipContainer(signedDocument);
	}

	@Override
	protected void onDocumentExtended(DSSDocument extendedDocument) {
		super.onDocumentExtended(extendedDocument);
		ASiCTestUtils.verifyZipContainer(extendedDocument);
	}

}
