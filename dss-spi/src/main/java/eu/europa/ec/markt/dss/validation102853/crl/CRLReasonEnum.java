package eu.europa.ec.markt.dss.validation102853.crl;

import java.util.HashMap;
import java.util.Map;

/**
 * This enum is used to get String value of CRLReason
 * 
 * The CRLReason enumeration.
 * 
 * <pre>
 * CRLReason ::= ENUMERATED {
 *  unspecified             (0),
 *  keyCompromise           (1),
 *  cACompromise            (2),
 *  affiliationChanged      (3),
 *  superseded              (4),
 *  cessationOfOperation    (5),
 *  certificateHold         (6),
 *  removeFromCRL           (8),
 *  privilegeWithdrawn      (9),
 *  aACompromise           (10)
 * }
 * </pre>
 */
public enum CRLReasonEnum {

	unspecified(0),

	keyCompromise(1),

	cACompromise(2),

	affiliationChanged(3),

	superseded(4),

	cessationOfOperation(5),

	certificateHold(6),

	unknow(7),

	removeFromCRL(8),

	privilegeWithdrawn(9),

	aACompromise(10);

	private final int value;

	private CRLReasonEnum(final int value) {
		this.value = value;
	}

	public static CRLReasonEnum fromInt(final int value) {
		for (CRLReasonEnum reason : CRLReasonEnum.values()) {
			if(reason.value == value) {
				return reason;
			}
		}
		return CRLReasonEnum.unknow;
	}

}
