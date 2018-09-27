package eu.europa.esig.dss.pades.signature.visible;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@RunWith(Suite.class)
@SuiteClasses(value = { PAdESSignatureField.class, PAdESVisibleSignature.class, PAdESFieldLevelB.class, PAdESWithSignatureAndTimestampVisible.class,
		PAdESWithSignatureInvisibleAndTimestampVisible.class })
public class PAdESVisibleSignatureSuite {

}
