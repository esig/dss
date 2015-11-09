package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;

public class MockDataLoader extends CommonsDataLoader {
	
	public MockDataLoader() {
	}
	
	@Override
	public byte[] get(final String urlString) {
		if(urlString.equals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf")) {
			DSSDocument document = new FileDocument("src/test/resources/validation/dss-728/politica_de_firma_anexo_1.pdf");
			return document.getBytes();
		} else {
			return super.get(urlString);
		}
	}
}
