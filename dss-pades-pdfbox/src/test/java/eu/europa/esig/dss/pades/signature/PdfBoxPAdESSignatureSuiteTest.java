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

import eu.europa.esig.dss.pades.signature.suite.CMSForPAdESGenerationServiceTest;
import eu.europa.esig.dss.pades.signature.suite.CertificateConflictTest;
import eu.europa.esig.dss.pades.signature.suite.DigestStabilityTest;
import eu.europa.esig.dss.pades.signature.suite.GetOriginalDocumentTest;
import eu.europa.esig.dss.pades.signature.suite.InvisibleSignatureFieldSignTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESAllSelfSignedCertsTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleLTAValidationDataTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignBAndExtendToLTATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureLTAAndLTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureLTAndTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESDoubleSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureBLevelTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureLTALevelDocTstTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureLTALevelTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureLTLevelDocTstTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureLTLevelTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureTLevelDocTstTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureTLevelTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESExternalCMSSignatureServiceTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBCertificationTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBCustomTimeZoneTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBDigestDocumentTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBEncryptedDocumentTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBExternalSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBHugeTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBLoopTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBNotEnoughSpaceForSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBOnlySigningCertTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBSignWithTempFileHandlerTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithAppNameTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithContentTimestampCustomDigestAlgoTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithContentTimestampTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithDSATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithECDSATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithECDSATokenTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithNoChangesPermittedTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithPlainECDSATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithPlainECDSATokenTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithSHA256andMGF1Test;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithValidationDataSameTstTrustAnchorTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelBWithValidationDataTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelImpossibleLTAExceptionTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelImpossibleLTExceptionTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTAAndLevelTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTANotTrustedTSPTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTASignDocumentWithXRefsTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTASignRevokedSigWithPOETest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTAWithSingleDocTstTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTAWithSingleSelfSignedDocTstTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTCRLCounterTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelLTWrongAIATest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelTNotTrustedTSPTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelTTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESLevelTWithSHA1MessageImprintTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESNoChangesPermittedTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESNoDuplicateValidationDataTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESServiceTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignDocumentWithEmptySignatureTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignDocumentsConsequentlyTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignWithAtomicMethodsTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignWithReInitParametersTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignWithRevokedCertTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignatureParametersSerializationTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSignedAssertionTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESSpaceEOFTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESTwoSignersLTALevelTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESWithPSSTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESWithPemEncodedCrlTest;
import eu.europa.esig.dss.pades.signature.suite.PAdESWithSHA3Test;
import eu.europa.esig.dss.pades.signature.suite.PDFSignWithPermissionsTest;
import eu.europa.esig.dss.pades.signature.suite.PDFSignatureWithoutCertificatesTest;
import eu.europa.esig.dss.pades.signature.suite.PDFTimestampFiltersTest;
import eu.europa.esig.dss.pades.signature.suite.ProtectedDocumentsSignatureTest;
import eu.europa.esig.dss.pades.signature.suite.TwoPAdESSignaturesMustHaveDifferentIdTest;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({ DigestStabilityTest.class, GetOriginalDocumentTest.class, PAdESDoubleSignatureTest.class, PAdESLevelBTest.class,
		PAdESLevelBExternalSignatureTest.class, PAdESLevelBLoopTest.class, PAdESLevelBNotEnoughSpaceForSignatureTest.class,
		PAdESLevelBOnlySigningCertTest.class, PAdESLevelBWithContentTimestampTest.class, PAdESLevelBWithDSATest.class,
		PAdESLevelBWithECDSATest.class, PAdESLevelBWithSHA256andMGF1Test.class,	PAdESLevelImpossibleLTAExceptionTest.class,
		PAdESLevelImpossibleLTExceptionTest.class, PAdESLevelLTTest.class, PAdESLevelLTATest.class, PAdESLevelLTWrongAIATest.class,
		PAdESLevelTTest.class, PDFTimestampFiltersTest.class, TwoPAdESSignaturesMustHaveDifferentIdTest.class, PAdESLevelBHugeTest.class,
		InvisibleSignatureFieldSignTest.class, PAdESSpaceEOFTest.class, PAdESDoubleLTAValidationDataTest.class,
		PAdESNoDuplicateValidationDataTest.class, PAdESWithPSSTest.class, PAdESWithSHA3Test.class, PAdESLevelTWithSHA1MessageImprintTest.class,
		PAdESAllSelfSignedCertsTest.class, PAdESServiceTest.class, CertificateConflictTest.class, ProtectedDocumentsSignatureTest.class,
		PAdESTwoSignersLTALevelTest.class, PAdESWithPemEncodedCrlTest.class, PAdESSignatureParametersSerializationTest.class,
		PAdESSignedAssertionTest.class, PAdESLevelLTAAndLevelTTest.class, PAdESLevelTNotTrustedTSPTest.class,
		PAdESLevelLTANotTrustedTSPTest.class, PAdESSignWithRevokedCertTest.class, PAdESLevelLTASignRevokedSigWithPOETest.class,
		PAdESLevelBCustomTimeZoneTest.class, PAdESLevelLTCRLCounterTest.class, PAdESLevelBWithPlainECDSATest.class,
        PAdESLevelBWithECDSATokenTest.class, PAdESLevelBWithPlainECDSATokenTest.class, PDFSignatureWithoutCertificatesTest.class,
		PAdESDoubleSignBAndExtendToLTATest.class, PDFSignWithPermissionsTest.class, PAdESNoChangesPermittedTest.class,
		PAdESLevelBWithNoChangesPermittedTest.class, PAdESLevelBCertificationTest.class, PAdESDoubleSignatureLTAAndLTTest.class,
		PAdESSignDocumentsConsequentlyTest.class, PAdESLevelBDigestDocumentTest.class, PAdESLevelBWithAppNameTest.class,
		PAdESLevelBSignWithTempFileHandlerTest.class, PAdESSignWithAtomicMethodsTest.class, PAdESSignWithReInitParametersTest.class,
		PAdESSignDocumentWithEmptySignatureTest.class, PAdESDoubleSignatureLTAndTTest.class, PAdESLevelLTASignDocumentWithXRefsTest.class,
		PAdESLevelBWithValidationDataTest.class, PAdESLevelBWithValidationDataSameTstTrustAnchorTest.class,
		PAdESLevelLTAWithSingleDocTstTest.class, PAdESLevelLTAWithSingleSelfSignedDocTstTest.class, PAdESExternalCMSSignatureBLevelTest.class,
		PAdESExternalCMSSignatureTLevelTest.class, PAdESExternalCMSSignatureLTLevelTest.class, PAdESExternalCMSSignatureLTALevelTest.class,
		PAdESExternalCMSSignatureTLevelDocTstTest.class, PAdESExternalCMSSignatureLTLevelDocTstTest.class,
		PAdESExternalCMSSignatureLTALevelDocTstTest.class, PAdESExternalCMSSignatureServiceTest.class, CMSForPAdESGenerationServiceTest.class,
		PAdESLevelBWithContentTimestampCustomDigestAlgoTest.class, PAdESLevelBEncryptedDocumentTest.class })
public class PdfBoxPAdESSignatureSuiteTest {

}
