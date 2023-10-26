/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PathsTest {
	
	@Test
	public void objectPath() {
		assertEquals("./ds:Object", XMLDSigPath.OBJECT_PATH);
	}

	@Test
	public void objectWithId() {
		String objectById = XMLDSigPath.OBJECT_PATH + DomUtils.getXPathByIdAttribute("bla");
		assertEquals("./ds:Object[@Id='bla' or @id='bla' or @ID='bla']", objectById);
	}

	@Test
	public void manifestPath() {
		assertEquals("./ds:Object/ds:Manifest", XMLDSigPath.MANIFEST_PATH);
	}

	@Test
	public void getSignedDataObjectPropertiesPath() {
		XAdESPath paths = new XAdES132Path();
		assertEquals("./ds:Object/xades132:QualifyingProperties/xades132:SignedProperties/xades132:SignedDataObjectProperties",
				paths.getSignedDataObjectPropertiesPath());
	}

	@Test
	public void allTimestamps() {
		XAdESPath paths = new XAdES132Path();
		String path = paths.getCurrentEncapsulatedTimestamp();
		assertEquals("./xades132:EncapsulatedTimeStamp", path);
	}

	@Test
	public void fromCurrentPosition() {
		XAdESPath paths = new XAdES132Path();
		String path = paths.getCurrentOCSPRefsChildren();
		assertEquals("./xades132:OCSPRefs/xades132:OCSPRef", path);
	}

	@Test
	public void notParentOf() {
		assertEquals("//ds:Signature[not(parent::xades132:CounterSignature)]", XAdES132Path.ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH);
	}

	@Test
	public void allFromCurrentPosition() {
		assertEquals(".//xades132:UnsignedProperties", AbstractPath.allFromCurrentPosition(XAdES132Element.UNSIGNED_PROPERTIES));
	}

}
