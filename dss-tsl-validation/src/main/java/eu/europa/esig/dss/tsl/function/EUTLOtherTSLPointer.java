package eu.europa.esig.dss.tsl.function;

/**
 * This class is a predicate which selects OtherTSLPointerType(s) with a defined
 * type equals to EUgeneric.
 */
public final class EUTLOtherTSLPointer extends TypeOtherTSLPointer {

	public static final String EXPECTED_EU_TL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";

	public EUTLOtherTSLPointer() {
		super(EXPECTED_EU_TL_TYPE);
	}

}
