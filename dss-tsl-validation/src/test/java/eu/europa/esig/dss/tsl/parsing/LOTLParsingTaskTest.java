package eu.europa.esig.dss.tsl.parsing;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.SchemeTerritoryOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class LOTLParsingTaskTest {

	private static DSSDocument LOTL;
	private static DSSDocument LOTL_NO_SIG;
	private static DSSDocument LOTL_NOT_PARSEABLE;
	private static DSSDocument LOTL_PIVOT;

	private static DSSDocument TL;

	@BeforeAll
	public static void init() throws IOException {
		LOTL = new FileDocument("src/test/resources/eu-lotl.xml");
		LOTL_NO_SIG = new FileDocument("src/test/resources/eu-lotl-no-sig.xml");
		LOTL_NOT_PARSEABLE = new FileDocument("src/test/resources/eu-lotl-not-parseable.xml");
		LOTL_PIVOT = new FileDocument("src/test/resources/eu-lotl-pivot.xml");

		TL = new FileDocument("src/test/resources/ie-tl.xml");
	}

	@Test
	public void parseLOTLDefault() {
		LOTLParsingTask task = new LOTLParsingTask(LOTL, new LOTLSource());
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		assertNull(result.getPivotURLs());

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		assertEquals(31, result.getTlPointers().size());
		checkOtherPointers(result.getTlPointers());
		assertEquals("EU", result.getTerritory());

		OtherTSLPointer otherTSLPointer = result.getLotlPointers().get(0);
		assertEquals(8, otherTSLPointer.getCertificates().size());
		assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml", otherTSLPointer.getLocation());

		assertNotNull(result.getDistributionPoints());
		assertEquals(1, result.getDistributionPoints().size());
	}

	@Test
	public void parseLOTLNoSig() {
		LOTLParsingTask task = new LOTLParsingTask(LOTL_NO_SIG, new LOTLSource());
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		assertNull(result.getPivotURLs());

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		assertEquals(31, result.getTlPointers().size());
		checkOtherPointers(result.getTlPointers());
		assertEquals("EU", result.getTerritory());

		assertNotNull(result.getDistributionPoints());
		assertEquals(1, result.getDistributionPoints().size());
	}

	private void checkOtherPointers(List<OtherTSLPointer> lotlPointers) {
		for (OtherTSLPointer otherTSLPointerDTO : lotlPointers) {
			assertNotNull(otherTSLPointerDTO);
			assertNotNull(otherTSLPointerDTO.getLocation());
			List<CertificateToken> certificates = otherTSLPointerDTO.getCertificates();
			assertNotNull(certificates);
			for (CertificateToken certificateToken : certificates) {
				assertNotNull(certificateToken);
			}
		}
	}

	@Test
	public void parseLOTLPivotSupport() {

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setPivotSupport(true);

		LOTLParsingTask task = new LOTLParsingTask(LOTL, lotlSource);
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());
		assertNull(result.getSigningCertificateAnnouncementURL());

		assertNotNull(result.getPivotURLs());
		assertEquals(0, result.getPivotURLs().size());

		assertEquals(1, result.getLotlPointers().size());
		assertEquals(31, result.getTlPointers().size());
		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void parseLOTLPivotSupportAndSigningCertAnnouncement() {

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setPivotSupport(true);
		lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI("https://eur-lex.europa.eu/legal-content/blabla"));

		LOTLParsingTask task = new LOTLParsingTask(LOTL, lotlSource);
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());

		assertNotNull(result.getPivotURLs());
		assertEquals(0, result.getPivotURLs().size());
		assertEquals("https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG",
				result.getSigningCertificateAnnouncementURL());

		assertEquals(1, result.getLotlPointers().size());
		assertEquals(31, result.getTlPointers().size());
		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void parseLOTLOnlyBEandPTPointers() {
		LOTLSource lotlSource = new LOTLSource();

		Set<String> countries = new HashSet<String>();
		countries.add("BE");
		countries.add("PT");

		lotlSource.setTlPredicate(new SchemeTerritoryOtherTSLPointer(countries).and(new XMLOtherTSLPointer()));

		LOTLParsingTask task = new LOTLParsingTask(LOTL, lotlSource);

		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(248, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		assertNull(result.getPivotURLs());

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		List<OtherTSLPointer> tlPointers = result.getTlPointers();
		assertEquals(2, tlPointers.size());
		checkOtherPointers(tlPointers);

		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void parsePivotLOTLDefault() {
		// not pivot support
		LOTLParsingTask task = new LOTLParsingTask(LOTL_PIVOT, new LOTLSource());
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(247, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		assertNull(result.getPivotURLs());

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		assertEquals(31, result.getTlPointers().size());
		checkOtherPointers(result.getTlPointers());
		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void parseTL() {
		// Should not fail
		LOTLParsingTask task = new LOTLParsingTask(TL, new LOTLSource());
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(18, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		assertNull(result.getPivotURLs());

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		assertEquals(0, result.getTlPointers().size());
		checkOtherPointers(result.getTlPointers());
		assertEquals("IE", result.getTerritory());

		OtherTSLPointer otherTSLPointer = result.getLotlPointers().get(0);
		assertEquals(8, otherTSLPointer.getCertificates().size());
		assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml", otherTSLPointer.getLocation());
	}

	@Test
	public void parsePivotLOTLWithPivotSupport() {

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setPivotSupport(true);

		LOTLParsingTask task = new LOTLParsingTask(LOTL_PIVOT, lotlSource);
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(247, result.getSequenceNumber());

		assertNull(result.getSigningCertificateAnnouncementURL());
		List<String> pivotURLs = result.getPivotURLs();
		assertNotNull(pivotURLs);
		assertEquals(4, pivotURLs.size());
		// Ensure original ordering
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml", pivotURLs.get(0));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml", pivotURLs.get(1));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", pivotURLs.get(2));
		assertEquals("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml", pivotURLs.get(3));

		assertEquals(1, result.getLotlPointers().size());
		checkOtherPointers(result.getLotlPointers());
		assertEquals(31, result.getTlPointers().size());
		checkOtherPointers(result.getTlPointers());
		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void notParseable() {
		LOTLParsingTask task = new LOTLParsingTask(LOTL_NOT_PARSEABLE, new LOTLSource());
		DSSException exception = assertThrows(DSSException.class, () -> task.get());
		assertTrue(exception.getMessage().contains("Unable to parse binaries"));
	}

}
