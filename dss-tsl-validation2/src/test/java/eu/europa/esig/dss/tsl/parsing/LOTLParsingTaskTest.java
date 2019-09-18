package eu.europa.esig.dss.tsl.parsing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.SchemeTerritoryOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public class LOTLParsingTaskTest {

	private static XmlDownloadResult LOTL;
	private static XmlDownloadResult LOTL_NO_SIG;
	private static XmlDownloadResult LOTL_NOT_PARSEABLE;
	private static XmlDownloadResult LOTL_PIVOT;

	private static XmlDownloadResult TL;

	@BeforeAll
	public static void init() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl.xml")) {
			LOTL = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}

		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl-no-sig.xml")) {
			LOTL_NO_SIG = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}

		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl-not-parseable.xml")) {
			LOTL_NOT_PARSEABLE = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}

		try (FileInputStream fis = new FileInputStream("src/test/resources/eu-lotl-pivot.xml")) {
			LOTL_PIVOT = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}

		try (FileInputStream fis = new FileInputStream("src/test/resources/ie-tl.xml")) {
			TL = new XmlDownloadResult("bla", Utils.toByteArray(fis), null);
		}
	}

	@Test
	public void parseLOTLDefault() {
		LOTLParsingTask task = new LOTLParsingTask(new LOTLSource(), LOTL);
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

		assertEquals(8, result.getLOTLAnnouncedSigningCertificates().size());

		assertNotNull(result.getDistributionPoints());
		assertEquals(1, result.getDistributionPoints().size());
	}

	@Test
	public void parseLOTLNoSig() {
		LOTLParsingTask task = new LOTLParsingTask(new LOTLSource(), LOTL_NO_SIG);
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

	private void checkOtherPointers(List<OtherTSLPointerDTO> lotlPointers) {
		for (OtherTSLPointerDTO otherTSLPointerDTO : lotlPointers) {
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

		LOTLParsingTask task = new LOTLParsingTask(lotlSource, LOTL);
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

		LOTLParsingTask task = new LOTLParsingTask(lotlSource, LOTL);
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

		LOTLParsingTask task = new LOTLParsingTask(lotlSource, LOTL);

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
		List<OtherTSLPointerDTO> tlPointers = result.getTlPointers();
		assertEquals(2, tlPointers.size());
		checkOtherPointers(tlPointers);

		assertEquals("EU", result.getTerritory());
	}

	@Test
	public void parsePivotLOTLDefault() {
		// not pivot support
		LOTLParsingTask task = new LOTLParsingTask(new LOTLSource(), LOTL_PIVOT);
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
		LOTLParsingTask task = new LOTLParsingTask(new LOTLSource(), TL);
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

		assertEquals(8, result.getLOTLAnnouncedSigningCertificates().size());
	}

	@Test
	public void parsePivotLOTLWithPivotSupport() {

		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setPivotSupport(true);

		LOTLParsingTask task = new LOTLParsingTask(lotlSource, LOTL_PIVOT);
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
		LOTLParsingTask task = new LOTLParsingTask(new LOTLSource(), LOTL_NOT_PARSEABLE);
		DSSException exception = assertThrows(DSSException.class, () -> task.get());
		assertEquals("Unable to parse binaries", exception.getMessage());
	}

}
