package eu.europa.esig.dss.pades.signature;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { DigestStability.class, GetOriginalDocument.class, PAdESBExtendToLTACheckTimeStampID.class, PAdESDoubleSignature.class,
		PAdESFieldLevelB.class, PAdESLevelB.class, PAdESLevelBExternalSignature.class, PAdESLevelBLoop.class, PAdESLevelBNotEnoughSpaceForSignature.class,
		PAdESLevelBOnlySigningCert.class, PAdESLevelBWithContentTimestamp.class, PAdESLevelBWithDSA.class, PAdESLevelBWithECDSA.class,
		PAdESLevelBWithMoreThanOneSecondDelay.class, PAdESLevelBWithSHA256andMGF1.class, PAdESLevelImpossibleLTAException.class,
		PAdESLevelImpossibleLTException.class, PAdESLevelLT.class, PAdESLevelLTA.class, PAdESLevelLTWrongAIA.class, PAdESLevelT.class,
		PAdESLTACheckTimeStampedTimestampID.class, PAdESLTACheckTimeStampID.class, PAdESSignatureField.class, PAdESVisibleSignature.class,
		PAdESWithSignatureAndTimestampVisible.class, PAdESWithSignatureInvisibleAndTimestampVisible.class, PAdESWithSignatureVisibleAndTimestampInvisible.class,
		PDFOverrideFilters.class, TwoPAdESSigniatureMustHaveDifferentId.class })
public class PAdESSignatureSuite {

}
