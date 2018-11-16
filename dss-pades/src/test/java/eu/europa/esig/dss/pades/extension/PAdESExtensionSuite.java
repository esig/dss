package eu.europa.esig.dss.pades.extension;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { PAdESExtensionBToLT.class, PAdESExtensionBToLTA.class, PAdESExtensionBToT.class, PAdESExtensionBToTWithCompositeTSA.class,
		PAdESExtensionBToTWithError500Timestamp.class, PAdESExtensionBToTWithFailTimestamp.class, PAdESExtensionLTAToLTA.class, PAdESExtensionLTToLTA.class,
		PAdESExtensionLTToLTAWithError500Timestamp.class, PAdESExtensionLTToLTAWithFailTimestamp.class, PAdESExtensionToLT.class,
		PAdESExtensionTToLTA.class, DSS1523.class })
public class PAdESExtensionSuite {

}
