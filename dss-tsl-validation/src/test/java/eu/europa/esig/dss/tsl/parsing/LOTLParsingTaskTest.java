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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LOTLParsingTaskTest {

	private static DSSDocument LOTL;
	private static DSSDocument LOTL_NO_SIG;
	private static DSSDocument LOTL_NOT_PARSEABLE;
	private static DSSDocument LOTL_PIVOT;

	private static DSSDocument LOTL_MRA;

	private static DSSDocument TL;

	@BeforeAll
	static void init() throws IOException {
		LOTL = new FileDocument("src/test/resources/eu-lotl.xml");
		LOTL_NO_SIG = new FileDocument("src/test/resources/eu-lotl-no-sig.xml");
		LOTL_NOT_PARSEABLE = new FileDocument("src/test/resources/eu-lotl-not-parseable.xml");
		LOTL_PIVOT = new FileDocument("src/test/resources/eu-lotl-pivot.xml");

		LOTL_MRA = new FileDocument("src/test/resources/mra-lotl.xml");

		TL = new FileDocument("src/test/resources/ie-tl.xml");
	}

	@Test
	void parseLOTLDefault() {
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
		assertEquals(8, otherTSLPointer.getSdiCertificates().size());
		assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml", otherTSLPointer.getTSLLocation());
		assertEquals("EU", otherTSLPointer.getSchemeTerritory());
		assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", otherTSLPointer.getTslType());
		assertEquals("application/vnd.etsi.tsl+xml", otherTSLPointer.getMimeType());
		assertEquals(1, otherTSLPointer.getSchemeOperatorNames().size());
		assertEquals("en", otherTSLPointer.getSchemeOperatorNames().keySet().iterator().next());
		assertEquals(1, otherTSLPointer.getSchemeOperatorNames().get("en").size());
		assertEquals("European Commission", otherTSLPointer.getSchemeOperatorNames().get("en").get(0));
		assertEquals(1, otherTSLPointer.getSchemeTypeCommunityRules().size());
		assertEquals("en", otherTSLPointer.getSchemeTypeCommunityRules().keySet().iterator().next());
		assertEquals(1, otherTSLPointer.getSchemeTypeCommunityRules().get("en").size());
		assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists", otherTSLPointer.getSchemeTypeCommunityRules().get("en").get(0));

		assertNotNull(result.getDistributionPoints());
		assertEquals(1, result.getDistributionPoints().size());
	}

	@Test
	void parseLOTLNoSig() {
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
			List<CertificateToken> certificates = otherTSLPointerDTO.getSdiCertificates();
			assertNotNull(certificates);
			for (CertificateToken certificateToken : certificates) {
				assertNotNull(certificateToken);
			}
			assertNotNull(otherTSLPointerDTO.getTSLLocation());
			assertNotNull(otherTSLPointerDTO.getSchemeTerritory());
			assertNotNull(otherTSLPointerDTO.getTslType());
			assertNotNull(otherTSLPointerDTO.getMimeType());
			assertNotNull(otherTSLPointerDTO.getSchemeOperatorNames());
			assertFalse(otherTSLPointerDTO.getSchemeOperatorNames().isEmpty());
			assertFalse(otherTSLPointerDTO.getSchemeTypeCommunityRules().isEmpty());
		}
	}

	@Test
	void parseLOTLPivotSupport() {

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
	void parseLOTLPivotSupportAndSigningCertAnnouncement() {

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
	void parseLOTLOnlyBEandPTPointers() {
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setTlPredicate(TLPredicateFactory.createEUTLCountryCodePredicate("BE", "PT"));

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
	void parsePivotLOTLDefault() {
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
	void parseLOTLMRA() {
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setMraSupport(true);
		lotlSource.setTlPredicate(new XMLOtherTSLPointer());
		LOTLParsingTask task = new LOTLParsingTask(LOTL_MRA, lotlSource);
		LOTLParsingResult result = task.get();
		assertNotNull(result);
		assertNotNull(result.getIssueDate());
		assertNotNull(result.getNextUpdateDate());
		assertEquals(5, result.getVersion());
		assertEquals(6, result.getSequenceNumber());
		assertEquals(33, result.getTlPointers().size());
		assertNotNull(result.getTlPointers().get(result.getTlPointers().size() - 1).getMra());
	}

	@Test
	void parseTL() {
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
		assertEquals(8, otherTSLPointer.getSdiCertificates().size());
		assertEquals("https://ec.europa.eu/tools/lotl/eu-lotl.xml", otherTSLPointer.getTSLLocation());
		assertEquals("EU", otherTSLPointer.getSchemeTerritory());
		assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", otherTSLPointer.getTslType());
		assertEquals("application/vnd.etsi.tsl+xml", otherTSLPointer.getMimeType());
		assertEquals(1, otherTSLPointer.getSchemeOperatorNames().size());
		assertEquals("en", otherTSLPointer.getSchemeOperatorNames().keySet().iterator().next());
		assertEquals(1, otherTSLPointer.getSchemeOperatorNames().get("en").size());
		assertEquals("European Commission", otherTSLPointer.getSchemeOperatorNames().get("en").get(0));
		assertEquals(1, otherTSLPointer.getSchemeTypeCommunityRules().size());
		assertEquals("en", otherTSLPointer.getSchemeTypeCommunityRules().keySet().iterator().next());
		assertEquals(1, otherTSLPointer.getSchemeTypeCommunityRules().get("en").size());
		assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists", otherTSLPointer.getSchemeTypeCommunityRules().get("en").get(0));
	}

	@Test
	void parsePivotLOTLWithPivotSupport() {

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
	void notParseable() {
		LOTLParsingTask task = new LOTLParsingTask(LOTL_NOT_PARSEABLE, new LOTLSource());
		DSSException exception = assertThrows(DSSException.class, task::get);
		assertTrue(exception.getMessage().contains("Unable to parse binaries"));
	}

}
