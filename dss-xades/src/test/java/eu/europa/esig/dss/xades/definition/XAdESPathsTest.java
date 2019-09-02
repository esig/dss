package eu.europa.esig.dss.xades.definition;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.definition.xmldsig.XMLDSigPaths;

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
		XAdESPaths paths = new XAdES132Paths();
		assertEquals("./ds:Object/xades132:QualifyingProperties/xades132:SignedProperties/xades132:SignedDataObjectProperties",
				paths.getSignedDataObjectPropertiesPath());
	}

	@Test
	public void allTimestamps() {
		XAdESPaths paths = new XAdES132Paths();
		String path = paths.getCurrentEncapsulatedTimestamp();
		assertEquals("./xades132:EncapsulatedTimeStamp", path);
	}

	@Test
	public void fromCurrentPosition() {
		XAdESPaths paths = new XAdES132Paths();
		String path = paths.getCurrentOCSPRefsChildren();
		assertEquals("./xades132:OCSPRefs/xades132:OCSPRef", path);
	}

}
