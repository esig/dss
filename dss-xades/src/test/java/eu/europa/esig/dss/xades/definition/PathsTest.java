/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.definition;

import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;
import eu.europa.esig.dss.xml.common.xpath.XPathQueryBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PathsTest {
	
	@Test
	void objectPath() {
		assertEquals("./ds:Object", XMLDSigPath.OBJECT_PATH.getQueryString());
	}

	@Test
	void objectWithId() {
		XPathQuery objectById = XPathQueryBuilder.fromXPathQuery(XMLDSigPath.OBJECT_PATH).idValue("bla").build();
		assertEquals("./ds:Object[@*[local-name()='Id']='bla' or @*[local-name()='id']='bla' or @*[local-name()='ID']='bla']", objectById.getQueryString());
	}

	@Test
	void manifestPath() {
		assertEquals("./ds:Object/ds:Manifest", XMLDSigPath.MANIFEST_PATH.getQueryString());
	}

	@Test
	void getSignedDataObjectPropertiesPath() {
		XAdESPath paths = new XAdES132Path();
		assertEquals("./ds:Object/xades132:QualifyingProperties/xades132:SignedProperties/xades132:SignedDataObjectProperties",
				paths.getSignedDataObjectPropertiesPath().getQueryString());
	}

	@Test
	void allTimestamps() {
		XAdESPath paths = new XAdES132Path();
		XPathQuery path = paths.getCurrentEncapsulatedTimestamp();
		assertEquals("./xades132:EncapsulatedTimeStamp", path.getQueryString());
	}

	@Test
	void fromCurrentPosition() {
		XAdESPath paths = new XAdES132Path();
		XPathQuery path = paths.getCurrentOCSPRefsChildren();
		assertEquals("./xades132:OCSPRefs/xades132:OCSPRef", path.getQueryString());
	}

	@Test
	void notParentOf() {
		assertEquals("//ds:Signature[not(parent::xades132:CounterSignature)]", XAdES132Path.ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH.getQueryString());
	}

	@Test
	void allFromCurrentPosition() {
		assertEquals(".//xades132:UnsignedProperties", AbstractPath.allFromCurrentPosition(XAdES132Element.UNSIGNED_PROPERTIES).getQueryString());
	}

}
