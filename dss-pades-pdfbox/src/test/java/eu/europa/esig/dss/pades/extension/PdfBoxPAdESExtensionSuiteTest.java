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
package eu.europa.esig.dss.pades.extension;

import eu.europa.esig.dss.pades.extension.suite.BuildKnownObjectsTest;
import eu.europa.esig.dss.pades.extension.suite.DSS1443Test;
import eu.europa.esig.dss.pades.extension.suite.DSS1469ExtensionTest;
import eu.europa.esig.dss.pades.extension.suite.DSS2058LTATest;
import eu.europa.esig.dss.pades.extension.suite.DSS2058QCLTATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionAllSelfSignedCertsTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTASelfSignedTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTAWithExpiredUserTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTWithRevokedCertTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTWithRevokedCertificateTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToLTWithRevokedSkipCheckTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToTTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToTWithCompositeTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToTWithError500TimestampTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToTWithFailTimestampTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionBToTWithRevokedCertTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionInvalidLevelsTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTAToLTATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTAToLTAWithDifferentTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTToLTASelfSignedTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTToLTATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTToLTAWithError500TimestampTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTToLTAWithFailTimestampTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionLTToLTAWithSelfSignedTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionNonPDFToLTALevelTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionNonPDFToLTLevelTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionNonPDFToTLevelTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTANoChangesPermittedTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTANotTrustedTSPTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTASelfSignedTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTAWithSelfSignedTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTSelfSignedTSATest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTTest;
import eu.europa.esig.dss.pades.extension.suite.PAdESExtensionTToLTWithSelfSignedTest;
import eu.europa.esig.dss.pades.extension.suite.PDFArchiveTimestampingTest;
import eu.europa.esig.dss.pades.extension.suite.PDFTimestampingTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({ PAdESExtensionBToLTTest.class, PAdESExtensionBToLTATest.class, PAdESExtensionBToTTest.class, PAdESExtensionBToTWithCompositeTSATest.class,
		PAdESExtensionBToTWithError500TimestampTest.class, PAdESExtensionBToTWithFailTimestampTest.class, PAdESExtensionLTAToLTATest.class,
		PAdESExtensionLTToLTATest.class, PAdESExtensionLTToLTAWithError500TimestampTest.class, PAdESExtensionLTToLTAWithFailTimestampTest.class,
		PAdESExtensionTToLTTest.class, PAdESExtensionTToLTATest.class, PAdESExtensionTToLTWithSelfSignedTest.class,
		PAdESExtensionTToLTAWithSelfSignedTest.class, PAdESExtensionLTToLTAWithSelfSignedTest.class, PAdESExtensionBToLTASelfSignedTSATest.class,
		PAdESExtensionTToLTSelfSignedTSATest.class, PAdESExtensionTToLTASelfSignedTSATest.class, PAdESExtensionLTToLTASelfSignedTSATest.class,
		PAdESExtensionAllSelfSignedCertsTest.class, PDFTimestampingTest.class, PDFArchiveTimestampingTest.class, DSS1443Test.class,
		DSS1469ExtensionTest.class, DSS2058LTATest.class, DSS2058QCLTATest.class, PAdESExtensionLTAToLTAWithDifferentTSATest.class,
		PAdESExtensionTToLTANotTrustedTSPTest.class, PAdESExtensionNonPDFToTLevelTest.class, PAdESExtensionNonPDFToLTLevelTest.class,
		PAdESExtensionNonPDFToLTALevelTest.class, PAdESExtensionBToLTWithRevokedCertificateTest.class,
		PAdESExtensionBToLTWithRevokedSkipCheckTest.class, BuildKnownObjectsTest.class, PAdESExtensionBToTWithRevokedCertTest.class,
		PAdESExtensionBToLTWithRevokedCertTest.class, PAdESExtensionBToLTAWithExpiredUserTest.class, PAdESExtensionTToLTANoChangesPermittedTest.class,
		PAdESExtensionInvalidLevelsTest.class })
public class PdfBoxPAdESExtensionSuiteTest {

}
