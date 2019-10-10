package eu.europa.esig.dss.tsl.cache.state;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.tsl.cache.CacheKey;

public class CacheKeyTest {
	
	@Test
	public void urlEncodingTest() {
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
	public void comparisonTest() {
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https://ec.europa.eu/tools/lotl/eu%20lotl.xml"));
		assertEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("https___ec_europa_eu_tools_lotl_eu_lotl_xml"));
		assertNotEquals(new CacheKey("https://ec.europa.eu/tools/lotl/eu-lotl.xml"), new CacheKey("http://www.neytendastofa.is/library/Files/TSl/tsl.pdf"));
		assertEquals(new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"), new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"));
		assertNotEquals(new CacheKey("https://www.nrca-ds.de/st/TSL-XML.xml"), new CacheKey("https://comunicatii.gov.ro/trustedlist.xml"));
	}

}
