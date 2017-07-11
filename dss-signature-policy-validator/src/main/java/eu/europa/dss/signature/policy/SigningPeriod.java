package eu.europa.dss.signature.policy;

import java.util.Date;

public interface SigningPeriod {

	Date getNotBefore();

	Date getNotAfter();

}