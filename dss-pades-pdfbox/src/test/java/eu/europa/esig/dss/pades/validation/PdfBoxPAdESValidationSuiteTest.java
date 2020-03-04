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
package eu.europa.esig.dss.pades.validation;

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

import eu.europa.esig.dss.pades.validation.suite.ASN1PolicyTest;
import eu.europa.esig.dss.pades.validation.suite.ArchiveTimestampCoverageTest;
import eu.europa.esig.dss.pades.validation.suite.DSS1188Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1376GetOriginalDocTest;
import eu.europa.esig.dss.pades.validation.suite.DSS1420Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1443Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1538Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1683Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1690Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1794Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1899Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1972Test;
import eu.europa.esig.dss.pades.validation.suite.DSS818Test;
import eu.europa.esig.dss.pades.validation.suite.DSS917Test;
import eu.europa.esig.dss.pades.validation.suite.DiagnosticDataCompleteTest;
import eu.europa.esig.dss.pades.validation.suite.EtsiValidationReportCompleteTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESCorruptedSigTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESInfiniteLoopTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESMultipleFieldSignatureReferenceTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESNonLatinCharactersValidationTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESTimestampWithOrphanRefsTest;
import eu.europa.esig.dss.pades.validation.suite.BadEncodedCMSTest;
import eu.europa.esig.dss.pades.validation.suite.PadesWrongDigestAlgoTest;
import eu.europa.esig.dss.pades.validation.suite.PdfPkcs7Test;
import eu.europa.esig.dss.pades.validation.suite.PolicyZeroHashTest;
import eu.europa.esig.dss.pades.validation.suite.SIWATest;
import eu.europa.esig.dss.pades.validation.suite.SignatureTimestampCertificateNotFoundTest;

@RunWith(JUnitPlatform.class)
@SelectClasses({ ASN1PolicyTest.class, DSS1188Test.class, DSS1376GetOriginalDocTest.class, DSS1420Test.class,
		DSS818Test.class, DSS917Test.class, PadesWrongDigestAlgoTest.class, PdfPkcs7Test.class, DSS1443Test.class,
		DSS1538Test.class, DSS1683Test.class, DSS1690Test.class, DiagnosticDataCompleteTest.class,
		EtsiValidationReportCompleteTest.class, SignatureTimestampCertificateNotFoundTest.class,
		PAdESCorruptedSigTest.class, PAdESNonLatinCharactersValidationTest.class, ArchiveTimestampCoverageTest.class,
		PolicyZeroHashTest.class, SIWATest.class, DSS1794Test.class, PAdESMultipleFieldSignatureReferenceTest.class,
		DSS1899Test.class, PAdESInfiniteLoopTest.class, PAdESTimestampWithOrphanRefsTest.class, DSS1972Test.class,
		BadEncodedCMSTest.class })
public class PdfBoxPAdESValidationSuiteTest {

}
