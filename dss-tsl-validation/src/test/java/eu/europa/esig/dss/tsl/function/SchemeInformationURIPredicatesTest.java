package eu.europa.esig.dss.tsl.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileInputStream;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class SchemeInformationURIPredicatesTest {

	private static NonEmptyMultiLangURIListType SCHEME_INFORMATION_URI_LIST_TYPE;

	@BeforeAll
	public static void init() throws Exception {
		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl-pivot.xml")) {
			TrustStatusListType lotlPivot = TrustedListFacade.newFacade().unmarshall(fis);
			assertNotNull(lotlPivot);
			SCHEME_INFORMATION_URI_LIST_TYPE = lotlPivot.getSchemeInformation().getSchemeInformationURI();
			assertNotNull(SCHEME_INFORMATION_URI_LIST_TYPE);
		}
	}

	@Test
	public void pivotLOTL() {
		List<String> pivotUrls = SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new PivotSchemeInformationURI()).map(t -> t.getValue())
				.collect(Collectors.toList());
		assertEquals(4, pivotUrls.size());

		// Ensure original ordering
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml", pivotUrls.get(0));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml", pivotUrls.get(1));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", pivotUrls.get(2));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml", pivotUrls.get(3));
	}

	@Test
	public void byLang() {
		assertEquals(1, SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new SchemeInformationURIByLang("fr")).count());
		assertEquals(0, SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new SchemeInformationURIByLang("xx")).count());
		assertThrows(NullPointerException.class, () -> new SchemeInformationURIByLang(null));
	}

	@Test
	public void oj() {

		String currentPivotOjUrl = "http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG";

		List<String> list = SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new OfficialJournalSchemeInformationURI(currentPivotOjUrl))
				.map(t -> t.getValue()).collect(Collectors.toList());
		assertEquals(1, list.size());
		assertEquals(currentPivotOjUrl, list.get(0));

		String otherOJUrl = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";
		list = SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new OfficialJournalSchemeInformationURI(otherOJUrl)).map(t -> t.getValue())
				.collect(Collectors.toList());
		assertEquals(1, list.size());
		assertEquals(currentPivotOjUrl, list.get(0));

		assertThrows(DSSException.class, () -> SCHEME_INFORMATION_URI_LIST_TYPE.getURI().stream().filter(new OfficialJournalSchemeInformationURI("blabla"))
				.collect(Collectors.toList()));
		assertThrows(NullPointerException.class, () -> new OfficialJournalSchemeInformationURI(null));

	}

}
