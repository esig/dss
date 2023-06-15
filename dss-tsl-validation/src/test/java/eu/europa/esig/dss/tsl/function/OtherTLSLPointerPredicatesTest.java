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
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.function.converter.OtherTSLPointerConverter;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OtherTLSLPointerPredicatesTest {

	@Test
	public void test() throws Exception {
		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl.xml")) {
			TrustStatusListType trustStatusListType = TrustedListFacade.newFacade().unmarshall(fis);
			assertNotNull(trustStatusListType);

			OtherTSLPointersType pointersToOtherTSL = trustStatusListType.getSchemeInformation().getPointersToOtherTSL();
			assertNotNull(pointersToOtherTSL);

			assertEquals(1, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new EULOTLOtherTSLPointer()).count());
			assertEquals(43, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new EUTLOtherTSLPointer()).count());

			assertEquals(12, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new PDFOtherTSLPointer()).count());
			assertEquals(32, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new XMLOtherTSLPointer()).count());
			assertEquals(12, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new XMLOtherTSLPointer().negate()).count());

			assertEquals(2, pointersToOtherTSL.getOtherTSLPointer().stream().filter(new SchemeTerritoryOtherTSLPointer("BG")).count());
			assertEquals(1,
					pointersToOtherTSL.getOtherTSLPointer().stream().filter(new SchemeTerritoryOtherTSLPointer("BG").and(new XMLOtherTSLPointer())).count());

			assertEquals(3, pointersToOtherTSL.getOtherTSLPointer().stream()
					.filter(new SchemeTerritoryOtherTSLPointer(new HashSet<>(Arrays.asList("BG", "CY")))).count());

			List<OtherTSLPointer> result = pointersToOtherTSL.getOtherTSLPointer().stream()
					.filter(new SchemeTerritoryOtherTSLPointer(new HashSet<>(Arrays.asList("BG", "CY")))).map(new OtherTSLPointerConverter(false))
					.collect(Collectors.toList());

			assertEquals(3, result.size());
			for (OtherTSLPointer otherTSLPointerDTO : result) {
				assertNotNull(otherTSLPointerDTO);
				assertNotNull(otherTSLPointerDTO.getTSLLocation());
				assertNotNull(otherTSLPointerDTO.getServiceDigitalIdentities());
				assertFalse(otherTSLPointerDTO.getServiceDigitalIdentities().isEmpty());
				assertNotNull(otherTSLPointerDTO.getSchemeTerritory());
				assertNotNull(otherTSLPointerDTO.getTslType());
				assertNotNull(otherTSLPointerDTO.getMimeType());
			}
		}
	}

	@Test
	public void exceptions() {
		assertThrows(NullPointerException.class, () -> new MimetypeOtherTSLPointer(null));
		assertThrows(NullPointerException.class, () -> new TypeOtherTSLPointer(null));
	}

}
