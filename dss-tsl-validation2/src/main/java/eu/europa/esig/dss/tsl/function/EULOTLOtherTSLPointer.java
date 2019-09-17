package eu.europa.esig.dss.tsl.function;

/**
 * This class is a predicate which selects OtherTSLPointerType(s) with a defined
 * type equals to EUlistofthelists.
 */
public final class EULOTLOtherTSLPointer extends TypeOtherTSLPointer {

	public static final String EXPECTED_EU_LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";

	public EULOTLOtherTSLPointer() {
		super(EXPECTED_EU_LOTL_TYPE);
	}

}
