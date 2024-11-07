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
package eu.europa.esig.dss.validation.executor.DSS2049;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.AbstractTestValidationExecutor;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DSS2049DoubleTLTest extends AbstractTestValidationExecutor {
	
	private static final String czId = "TL-57FCA8BD35213403F3B984949365A5B03DB909F620AFE49D66A1470F964C551F";
	private static final String skId = "TL-E9B06DA147E169206B0CC37F5202CC878097444EF14D52EA2042871139986DAC";

	@Test
	void test() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.QESIG, true, true, true);
	}
	
	@Test
	void lotlFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true, true);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, true, true, true);
	}
	
	@Test
	void lotlFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(false, true, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.NA, false, false, false);
	}
	
	@Test
	void czFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, true);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, true, true, true);
	}
	
	@Test
	void czFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, true);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.QESIG, true, false, true);
	}
	
	@Test
	void skFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, false);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, true, true, true);
	}
	
	@Test
	void skFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, true, false);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.QESIG, true, true, false);
	}
	
	@Test
	void bothFailWithWarnLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, false);
		Reports reports = execute(diagnosticData, Level.WARN);
		assertValid(reports, SignatureQualification.QESIG, true, true, true);
	}
	
	@Test
	void bothFailWithFailLevel() throws Exception {
		XmlDiagnosticData diagnosticData = getDiagnosticData(true, false, false);
		Reports reports = execute(diagnosticData, Level.FAIL);
		assertValid(reports, SignatureQualification.NA, true, false, false);
	}
	
	private XmlDiagnosticData getDiagnosticData(boolean isLOTLWellSigned, boolean czTLWellSigned, boolean skTLWellSigned) throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
				new File("src/test/resources/diag-data/DSS-2049/dss2049-doubleTL.xml"));
		assertNotNull(diagnosticData);
		
		List<XmlTrustedList> trustedLists = diagnosticData.getTrustedLists();
		assertEquals(3, trustedLists.size());
		XmlTrustedList xmlLOTL = trustedLists.get(0);
		xmlLOTL.setWellSigned(isLOTLWellSigned);
		XmlTrustedList xmlCZTL = trustedLists.get(1);
		xmlCZTL.setWellSigned(czTLWellSigned);
		XmlTrustedList xmlSKTL = trustedLists.get(2);
		xmlSKTL.setWellSigned(skTLWellSigned);
		
		return diagnosticData;
	}
	
	private Reports execute(XmlDiagnosticData diagnosticData, Level tlWellSignedlLevel) throws Exception {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		
		ValidationPolicy defaultPolicy = loadDefaultPolicy();
		EIDAS eidasConstraints = defaultPolicy.getEIDASConstraints();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(tlWellSignedlLevel);
		eidasConstraints.setTLWellSigned(levelConstraint);
		
		executor.setValidationPolicy(defaultPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		return executor.execute();
	}
	
	private void assertValid(Reports reports, SignatureQualification sigQual, 
			boolean assertLOTLValid, boolean assertCZTLValid, boolean assertSKTLValid) {
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(sigQual, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		
		List<XmlSignature> signatures = detailedReport.getSignatures();
		assertEquals(1, signatures.size());
		XmlSignature xmlSignature = signatures.get(0);
		
		XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
		List<XmlConstraint> constraints = validationSignatureQualification.getConstraint();
		
		int lotlsProcessed = 0;
		int tlsProcessed = 0;
		boolean isLOTLValid = false;
		boolean isCZTLValid = false;
		boolean isSKTLValid = false;
		boolean acceptableFound = false;
		for (XmlConstraint constraint : constraints) {
			if (MessageTag.QUAL_LIST_OF_TRUSTED_LISTS_ACCEPT.name().equals(constraint.getName().getKey())) {
				++lotlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					isLOTLValid = true;
				}
			} else if (MessageTag.QUAL_TRUSTED_LIST_ACCEPT.name().equals(constraint.getName().getKey())) {
				++tlsProcessed;
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					if (czId.equals(constraint.getId())) {
						isCZTLValid = true;
					} else if (skId.equals(constraint.getId())) {
						isSKTLValid = true;
					}
				}
			} else if (MessageTag.QUAL_VALID_TRUSTED_LIST_PRESENT.name().equals(constraint.getName().getKey())) {
				if (XmlStatus.OK.equals(constraint.getStatus())) {
					acceptableFound = true;
				}
			}
		}
		assertEquals(1, lotlsProcessed);
		assertEquals(assertLOTLValid ? 2 : 0, tlsProcessed);
		assertEquals(assertLOTLValid, isLOTLValid);
		assertEquals(assertCZTLValid, isCZTLValid);
		assertEquals(assertSKTLValid, isSKTLValid);
		assertEquals(assertLOTLValid && (assertCZTLValid || assertSKTLValid), acceptableFound);
	}

}
