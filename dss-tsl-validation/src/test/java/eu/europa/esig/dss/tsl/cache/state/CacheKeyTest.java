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
package eu.europa.esig.dss.tsl.cache.state;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.tsl.cache.CacheKey;

class CacheKeyTest {
	
	@Test
	void urlEncodingTest() {
		assertEquals("https___ec_europa_eu_tools_lotl_eu_lotl_xml", new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml").getKey());
		assertEquals("https___ec_europa_eu_tools_lotl_eu_lotl_xml", new CacheKey("https___ec_europa_eu_tools_lotl_eu_lotl_xml").getKey());
		assertEquals("https___ec_europa_eu_tools_lotl_eu_lotl_xml", new CacheKey("https://ec.europa.eu/tools/lotl/eu lotl.xml").getKey());
		assertEquals("https___ec_europa_eu_tools_lotl_eu_lotl_xml", new CacheKey("https://ec.europa.eu/tools/lotl/eu%20lotl.xml").getKey());
		assertEquals("http___www_neytendastofa_is_library_Files_TSl_tsl_pdf", new CacheKey("http://www.neytendastofa.is/library/Files/TSl/tsl.pdf").getKey());
		assertEquals("https___www_nrca_ds_de_st_TSL_XML_xml", new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml").getKey());
		assertEquals("https___comunicatii_gov_ro_trustedlist_xml", new CacheKey("https://comunicatii.gov.ro/trustedlist.xml").getKey());
		assertEquals("http___tl_nbu_gov_sk_kca_tsl_tsl_xml", new CacheKey("http://tl.nbu.gov.sk/kca/tsl/tsl.xml").getKey());
	}
	
	@Test
	void comparisonTest() {
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu%20lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https___ec_europa_eu_tools_lotl_eu_lotl_xml"));
		assertNotEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("http://www.neytendastofa.is/library/Files/TSl/tsl.pdf"));
		assertEquals(new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"), new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"));
		assertNotEquals(new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"), new CacheKey("https://comunicatii.gov.ro/trustedlist.xml"));
	}

}
