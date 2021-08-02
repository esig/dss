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

import eu.europa.esig.dss.pades.validation.suite.ASN1PolicyTest;
import eu.europa.esig.dss.pades.validation.suite.BadEncodedCMSTest;
import eu.europa.esig.dss.pades.validation.suite.DSS1188Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1376GetOriginalDocTest;
import eu.europa.esig.dss.pades.validation.suite.DSS1523Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1538Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1683Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1690Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1972Test;
import eu.europa.esig.dss.pades.validation.suite.DSS1983Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2023Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2025Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2116WithPAdESTest;
import eu.europa.esig.dss.pades.validation.suite.DSS2155Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2199Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2258Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2451Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2471Test;
import eu.europa.esig.dss.pades.validation.suite.DSS2513LTTest;
import eu.europa.esig.dss.pades.validation.suite.DSS2513Test;
import eu.europa.esig.dss.pades.validation.suite.PAdESEnvelopingOtherPdfTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESExtendedToTLevelTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESInfiniteLoopTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESInvalidDigestAlgorithmTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESMultipleFieldSignatureReferenceTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESMultiplePagesAnnotationsOverlapTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESOCSPSigningCertificateTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESOutOfByteRangeTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESOverwrittenDSSDictTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESSameBorderAnnotationsTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESSimpleCorruptedTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESSimpleValidationTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESTimestampWithOrphanRefsTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithAddedPageTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithCrossCertificateOCSPsTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithDssVriAndCertRefTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithOcspFromDssRevisionTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithOrphanOcspCertRefsTest;
import eu.europa.esig.dss.pades.validation.suite.PAdESWithRemovedPagesTest;
import eu.europa.esig.dss.pades.validation.suite.PadesWrongDigestAlgoTest;
import eu.europa.esig.dss.pades.validation.suite.PdfPkcs7Test;
import eu.europa.esig.dss.pades.validation.suite.PdfPkcs7WithSha1SubFilterTest;
import eu.europa.esig.dss.pades.validation.suite.PolicyZeroHashTest;
import eu.europa.esig.dss.pades.validation.suite.SIWATest;
import eu.europa.esig.dss.pades.validation.suite.SignatureTimestampCertificateNotFoundTest;
import eu.europa.esig.dss.pades.validation.suite.TimestampedAndSignedTest;
import eu.europa.esig.dss.pades.validation.suite.dss1420.DSS1420Sha224Test;
import eu.europa.esig.dss.pades.validation.suite.dss1420.DSS1420Test;
import eu.europa.esig.dss.pades.validation.suite.dss1469.DSS1469LTTest;
import eu.europa.esig.dss.pades.validation.suite.dss1469.DSS1469Test;
import eu.europa.esig.dss.pades.validation.suite.dss1696.ArchiveTimestampCoverageTest;
import eu.europa.esig.dss.pades.validation.suite.dss1696.DoubleArchiveTstCoverageTest;
import eu.europa.esig.dss.pades.validation.suite.dss1794.DSS1794CrlTest;
import eu.europa.esig.dss.pades.validation.suite.dss1794.DSS1794OcspTest;
import eu.europa.esig.dss.pades.validation.suite.dss1899.DSS1899Test;
import eu.europa.esig.dss.pades.validation.suite.dss1899.DSS1899TstWithNullTypeTest;
import eu.europa.esig.dss.pades.validation.suite.dss818.DSS818ADOTest;
import eu.europa.esig.dss.pades.validation.suite.dss818.DSS818CRYTest;
import eu.europa.esig.dss.pades.validation.suite.dss818.DSS818SKTest;
import eu.europa.esig.dss.pades.validation.suite.dss917.DSS917CorruptedTest;
import eu.europa.esig.dss.pades.validation.suite.dss917.DSS917Test;
import eu.europa.esig.dss.pades.validation.suite.revocation.PAdESDssAndVriTest;
import eu.europa.esig.dss.pades.validation.suite.revocation.PAdESFiveSignaturesDocTest;
import eu.europa.esig.dss.pades.validation.suite.revocation.PAdESMultiSignedDocRevocTest;
import eu.europa.esig.dss.pades.validation.suite.revocation.PAdESRevocationOriginTest;
import eu.europa.esig.dss.pades.validation.suite.revocation.PAdESSignatureDigestReferenceTest;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
@SelectClasses({ ASN1PolicyTest.class, DSS1188Test.class, DSS1376GetOriginalDocTest.class, DSS1420Test.class, DSS1420Sha224Test.class,
		DSS818CRYTest.class, DSS818ADOTest.class, DSS818SKTest.class, DSS917Test.class, DSS917CorruptedTest.class, PadesWrongDigestAlgoTest.class,
		PdfPkcs7Test.class, DSS1538Test.class, DSS1683Test.class, DSS1690Test.class, PAdESRevocationOriginTest.class, PAdESMultiSignedDocRevocTest.class,
		PAdESDssAndVriTest.class, PAdESFiveSignaturesDocTest.class, PAdESSignatureDigestReferenceTest.class, PAdESSignatureDigestReferenceTest.class,
		SignatureTimestampCertificateNotFoundTest.class, PAdESSimpleValidationTest.class, PAdESSimpleCorruptedTest.class, PAdESOutOfByteRangeTest.class,
		ArchiveTimestampCoverageTest.class, DoubleArchiveTstCoverageTest.class, PolicyZeroHashTest.class, SIWATest.class, DSS1794CrlTest.class,
		DSS1794OcspTest.class, PAdESMultipleFieldSignatureReferenceTest.class, DSS1899Test.class, DSS1899TstWithNullTypeTest.class, PAdESInfiniteLoopTest.class,
		PAdESTimestampWithOrphanRefsTest.class, DSS1972Test.class, BadEncodedCMSTest.class, PAdESWithOrphanOcspCertRefsTest.class, DSS1983Test.class,
		DSS1469Test.class, DSS1469LTTest.class, DSS1523Test.class, PAdESOCSPSigningCertificateTest.class, PAdESWithDssVriAndCertRefTest.class,
		PAdESWithOcspFromDssRevisionTest.class, PAdESInvalidDigestAlgorithmTest.class, DSS2023Test.class, DSS2025Test.class, DSS2116WithPAdESTest.class,
		PAdESExtendedToTLevelTest.class, DSS2199Test.class, PAdESSameBorderAnnotationsTest.class, PAdESMultiplePagesAnnotationsOverlapTest.class,
		PAdESWithAddedPageTest.class, PAdESWithRemovedPagesTest.class, DSS2258Test.class, TimestampedAndSignedTest.class, DSS2155Test.class,
		DSS2451Test.class, PAdESOverwrittenDSSDictTest.class, DSS2471Test.class, PAdESWithCrossCertificateOCSPsTest.class,
		PAdESEnvelopingOtherPdfTest.class, PdfPkcs7WithSha1SubFilterTest.class, DSS2513Test.class, DSS2513LTTest.class })
public class ITextPAdESValidationSuiteTest {

}
