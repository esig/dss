package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithNewLineMimeTypeTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/asice-cades-new-line-mimetype");
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);
		assertEquals("ASiC-E", containerInfo.getContainerType());
		assertEquals("mimetype=application/vnd.etsi.asic-e+zip\n", containerInfo.getZipComment());
		assertTrue(containerInfo.isMimeTypeFilePresent());
		assertEquals("application/vnd.etsi.asic-e+zip\r\n", containerInfo.getMimeTypeContent());
	}

}
