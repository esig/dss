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
package eu.europa.esig.dss.asic.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;

public class ASiCUtilsTest {

	@Test
	public void isZip() {
		assertFalse(ASiCUtils.isZip(null));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 0 })));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'P' })));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'p', 'k' })));
		assertThrows(NullPointerException.class, () -> ASiCUtils.isZip(new InMemoryDocument()));

		assertTrue(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'K' })));
	}

	@Test
	public void getASiCContainerType() {
		MimeType mt = new MimeType();
		mt.setMimeTypeString("application/vnd.etsi.asic-e+zip");
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(mt));

		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeType.ASICE));
	}

	@Test
	public void getWrongASiCContainerType() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			MimeType mt = new MimeType();
			mt.setMimeTypeString("application/wrong");
			ASiCUtils.getASiCContainerType(mt);
		});
		assertEquals("Not allowed mimetype 'application/wrong'", exception.getMessage());
	}

}
