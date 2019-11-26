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
package eu.europa.esig.dss.pades.signature;

import org.junit.platform.runner.JUnitPlatform;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.runner.RunWith;

import eu.europa.esig.dss.pades.signature.suite.DigestStabilityTest;
import eu.europa.esig.dss.pades.signature.suite.GetOriginalDocumentTest;
import eu.europa.esig.dss.pades.signature.suite.InvisibleSignatureFieldSignTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESAllSelfSignedCertsTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESBExtendToLTACheckTimeStampIDTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleLTAValidationDataTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLTACheckTimeStampIDTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLTACheckTimeStampedTimestampIDTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBExternalSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBHugeTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBLoopTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBNotEnoughSpaceForSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBOnlySigningCertTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithContentTimestampTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithDSATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithECDSATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithMoreThanOneSecondDelayTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithSHA256andMGF1Test;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelImpossibleLTAExceptionTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelImpossibleLTExceptionTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTWrongAIATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelTWithSHA1MessageImprintTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESNoDuplicateValidationDataTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESServiceTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSpaceEOFTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESWithPSSTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESWithSHA3Test;
import eu.europa.esig.dss.pades.signature.suite.PDFOverrideFiltersTest;
import eu.europa.esig.dss.pades.signature.suite.TwoPAdESSigniatureMustHaveDifferentIdTest;

@RunWith(JUnitPlatform.class)
@SelectClasses({ DigestStabilityTest.class, GetOriginalDocumentTest.class, PAdESBExtendToLTACheckTimeStampIDTest.class, PAdESDoubleSignatureTest.class, PAdESLevelBTest.class,
		PAdESLevelBExternalSignatureTest.class, PAdESLevelBLoopTest.class, PAdESLevelBNotEnoughSpaceForSignatureTest.class, PAdESLevelBOnlySigningCertTest.class,
		PAdESLevelBWithContentTimestampTest.class, PAdESLevelBWithDSATest.class, PAdESLevelBWithECDSATest.class, PAdESLevelBWithMoreThanOneSecondDelayTest.class,
		PAdESLevelBWithSHA256andMGF1Test.class, PAdESLevelImpossibleLTAExceptionTest.class, PAdESLevelImpossibleLTExceptionTest.class, PAdESLevelLTTest.class,
		PAdESLevelLTATest.class, PAdESLevelLTWrongAIATest.class, PAdESLevelTTest.class, PAdESLTACheckTimeStampedTimestampIDTest.class, PAdESLTACheckTimeStampIDTest.class,
		PDFOverrideFiltersTest.class, TwoPAdESSigniatureMustHaveDifferentIdTest.class, PAdESLevelBHugeTest.class, InvisibleSignatureFieldSignTest.class, PAdESSpaceEOFTest.class,
		PAdESDoubleLTAValidationDataTest.class, PAdESNoDuplicateValidationDataTest.class, PAdESWithPSSTest.class, PAdESWithSHA3Test.class,
		PAdESLevelTWithSHA1MessageImprintTest.class, PAdESAllSelfSignedCertsTest.class, PAdESServiceTest.class })
public class ITextPAdESSignatureTest {

}
