package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import static org.junit.Assert.assertEquals;

import java.util.Date;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlRFC;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.SubContext;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.bbb.LoadPolicyUtils;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;

public class RevocationFreshnessCheckerTest {

	@Test
	public void revocationDataFreshWithTimeConstraintCheck() throws Exception {
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		XmlBasicSignature xbs = new XmlBasicSignature();
		xbs.setEncryptionAlgoUsedToSignThisToken("RSA");
		xbs.setDigestAlgoUsedToSignThisToken("SHA1");
		xbs.setKeyLengthUsedToSignThisToken("2048");

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 129600000)); // 36 hours ago
		xr.setNextUpdate(new Date(nowMil - 43200000)); // 12 hours ago -> max
														// freshness is 24 hours
		xr.setBasicSignature(xbs);

		xr.setProductionDate(new Date(nowMil - 108000000)); // 30 hours ago ->
															// should not be
															// considered fresh

		RevocationFreshnessChecker rfc = new RevocationFreshnessChecker(new RevocationWrapper(xr), now,
				Context.REVOCATION, SubContext.CA_CERTIFICATE, policy);
		XmlRFC result = rfc.execute();

		assertEquals(Indication.FAILED, result.getConclusion().getIndication());
	}

}
