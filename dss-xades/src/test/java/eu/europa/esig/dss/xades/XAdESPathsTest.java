package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class XAdESPathsTest {
	
	@Test
	public void objectPath() {
		assertEquals("./ds:Object", XMLDSigPaths.OBJECT_PATH);
	}

	@Test
	public void manifestPath() {
		assertEquals("./ds:Object/ds:Manifest", XMLDSigPaths.MANIFEST_PATH);
	}

	@Test
	public void getSignedDataObjectPropertiesPath() {
		XAdESPaths paths = new XAdESPaths();
		assertEquals("./ds:Object/xades:QualifyingProperties/xades:SignedProperties/xades:SignedDataObjectProperties",
				paths.getSignedDataObjectPropertiesPath());
	}

	@Test
	public void allTimestamps() {
		String path = XAdESPaths.all(XAdES132Element.ENCAPSULATED_TIMESTAMP);
		assertEquals("//xades:EncapsulatedTimeStamp", path);
	}

	@Test
	public void fromCurrentPosition() {
		String path = XAdESPaths.fromCurrentPosition(XAdES132Element.OCSP_REF);
		assertEquals("./xades:OCSPRef", path);
	}

	@Test
	public void fromCurrentPositionMultiple() {
		String path = XAdESPaths.fromCurrentPosition(XAdES132Element.OCSP_REFS, XAdES132Element.OCSP_REF);
		assertEquals("./xades:OCSPRefs/xades:OCSPRef", path);
	}

}
