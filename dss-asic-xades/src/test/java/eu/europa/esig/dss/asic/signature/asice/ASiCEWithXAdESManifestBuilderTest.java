package eu.europa.esig.dss.asic.signature.asice;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class ASiCEWithXAdESManifestBuilderTest {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithXAdESManifestBuilderTest.class);

	@Test
	public void test() {
		DSSDocument d1 = new InMemoryDocument("hello".getBytes(), "test.txt");
		DSSDocument d2 = new InMemoryDocument("world".getBytes(), "test.html");
		DSSDocument d3 = new InMemoryDocument("bye".getBytes(), "test.pdf");
		List<DSSDocument> documents = Arrays.asList(d1, d2, d3);
		ASiCEWithXAdESManifestBuilder builder = new ASiCEWithXAdESManifestBuilder(documents);
		Document doc = builder.build();
		String xmlContent = new String(DSSXMLUtils.serializeNode(doc));
		LOG.info(xmlContent);

		// <?xml version="1.0" encoding="UTF-8" standalone="no"?>
//		<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
//			<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
//			<manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
//			<manifest:file-entry manifest:full-path="test.html" manifest:media-type="text/html"/>
//			<manifest:file-entry manifest:full-path="test.pdf" manifest:media-type="application/pdf"/>
//		</manifest:manifest> 

		assertTrue(xmlContent.contains("xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"test.txt\""));
		assertTrue(xmlContent.contains("manifest:media-type=\"application/vnd.etsi.asic-e+zip\""));
	}

}
