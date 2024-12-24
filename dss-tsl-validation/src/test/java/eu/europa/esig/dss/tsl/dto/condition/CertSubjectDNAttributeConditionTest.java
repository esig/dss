/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.dto.condition;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.trustedlist.enums.Assert;

class CertSubjectDNAttributeConditionTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertSubjectDNAttributeConditionTest.class);

	@Test
	void test() {
		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");

		LOG.info(certificate.getSubject().getPrincipal().getName());

		CertSubjectDNAttributeCondition csdnac = new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString()));
		LOG.info(csdnac.toString());
		assertTrue(csdnac.check(certificate));

		csdnac = new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.EmailAddress.toString()));
		LOG.info(csdnac.toString());
		assertFalse(csdnac.check(certificate));
	}

	@Test
	void dss1911() {
		CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIG6jCCBNKgAwIBAgIKAegBhfr9CQACpjANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJTSzETMBEGA1UEBwwKQnJhdGlzbGF2YTEXMBUGA1UEBRMOTlRSU0stMzYwNjE3MDExIjAgBgNVBAoMGU5hcm9kbnkgYmV6cGVjbm9zdG55IHVyYWQxDDAKBgNVBAsMA1NFUDEOMAwGA1UEAwwFU05DQTMwHhcNMTkwMjI1MTE0NTQ0WhcNMjEwMjI0MTE0NTQ0WjCB8zELMAkGA1UEBhMCU0sxDjAMBgNVBBEMBTg1MTA2MTAwLgYDVQQHDCdCcmF0aXNsYXZhIC0gbWVzdHNrw6EgxI1hc8WlIFBldHLFvmFsa2ExFzAVBgNVBAkMDkJ1ZGF0w61uc2thIDMwMRMwEQYLKwYBBAGCNzwCAQMMAkVVMRowGAYDVQQPDBFHb3Zlcm5tZW50IEVudGl0eTEXMBUGA1UEBRMOTlRSU0stMzYwNjE3MDExJzAlBgNVBAoMHk7DoXJvZG7DvSBiZXpwZcSNbm9zdG7DvSDDunJhZDEWMBQGA1UEAwwNdGwubmJ1Lmdvdi5zazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALs7qOQsbZZjQ7pL/1zgwNRjBgaSLkRxbi9LfXX2BNBt5GpHYsSfvw3YBtDgEfEE1RtqR3ktyw2yEQaH/52Okf5UhZTd8F4XKaitnqpFQkxtxoxR1eNTdnpc6EU5OYawNAwaSfnVok1vbvu6OhE2NVSiverFRMrHi26H/m0BiVUIDqw/DP11dJRvIHie5Ldt+XfJ9E5oiV+/iaHM4WFd7TDO2MZmRKqV8SsmljHpluVGu9ntSVJlW8PokDRSDchrLqSZvSsg76BEzohFlVubpNxdQIAOdzCC0I0YTp+WxpPuWLVn0RhCOwuwLQ6VfcNQEoIMvOlR/OMfb5D51z5PqjUCAwEAAaOCAfMwggHvMIGgBggrBgEFBQcBAQSBkzCBkDAzBggrBgEFBQcwAYYnaHR0cDovL3NuY2EzLW9jc3AubmJ1Lmdvdi5zay9vY3NwL3NuY2EzMDYGCCsGAQUFBzAChipodHRwOi8vZXAubmJ1Lmdvdi5zay9zbmNhL2NlcnRzMy9zbmNhMy5wN2MwIQYIKwYBBQUHMAKkFTATMREwDwYDVQQFEwhUTElTSy04MjAdBgNVHQ4EFgQUlSCdtY3rt/LHmVzsNx29rhT25CkwHwYDVR0jBBgwFoAUKaIHEeYMKI6axfcIS0LG1RwNvOIwDAYDVR0TAQH/BAIwADBpBgNVHSAEYjBgMA8GDSuBHpGZhAUAAAABAgIwRAYKK4EekZmEBQABAjA2MDQGCCsGAQUFBwIBFihodHRwOi9lcC5uYnUuZ292LnNrL3NuY2EvZG9jL2NwX3NuY2EucGRmMAcGBWeBDAEBMAsGA1UdDwQEAwIEsDATBgNVHSUEDDAKBggrBgEFBQcDATA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY2RwLm5idS5nb3Yuc2svc25jYS9jcmxzMy9zbmNhMy5jcmwwGAYIKwYBBQUHAQMEDDAKMAgGBgQAjkYBATAYBgNVHREEETAPgg10bC5uYnUuZ292LnNrMA0GCSqGSIb3DQEBCwUAA4ICAQBf7OIaTY3Aq2pmgEzjFMfVBrhj3XQPn//oAKqo3mPtuBtjd75E709wJH77joUzqFSN+6Exj4lPfoKSOi3uBwmnQBNkSBJ9N+99rGO8JvalD65Eaq8eaRwBzYMnaQm+DiezSKQmV9ouu412R5K6zKvNLHcjT0/wGN7E1gEyZIwpl1YXD9jsIghTfeU4q6S4mbPNiexARDOkAG2SNZw+G7wO+xvXBgPb8uO5xcmWGB6Re6K0KsT3YZO8md1t3tKOpGsPGmdjn4eyOxzS/8twa3fe/RZHOmYCMnQhCMmPyGYNoM269LTdo4kTYgTOi/ZuXDHp7Ncnz3C62XGsH6utREIHQ7VLfDOjycvx4REYQag3nJZaa8nmrbou8nGBDMvWzEvGkCQVTNqUNHqzuAFMyOqEvjyrD9pY4ARYYwEmdL1bd04F/nA5J2VgWQJC+DF3v1Mwl88ysfm5tYZJFMoo4gu4Kj5c05MgAX9X5xRXR2GgN/Xf3r6F3wEOEDDNemxGJdylljaD4e8uHiStOy9aEqXPNNFuhCL+uuLQeoMbop9B6uJ7NsCq9z5sqeo6Nj6OQS/03cx/mUgQRCTW7u81WbYIiL+1Oa540tsuJBvqiKUhp92xJhoPvEqgQ/plgsiIkZX8jFpmRU78m88Hz9KM1GY57D81xh0t0R6PRQS8KXWceA==");

		LOG.info(certificate.getSubject().getPrincipal().getName());

		CompositeCondition allNones = new CompositeCondition(Assert.ALL);

		CompositeCondition none42 = new CompositeCondition(Assert.NONE);
		none42.addChild(new CertSubjectDNAttributeCondition(Arrays.asList("2.5.4.42")));

		CompositeCondition none65 = new CompositeCondition(Assert.NONE);
		none65.addChild(new CertSubjectDNAttributeCondition(Arrays.asList("2.5.4.65")));

		CompositeCondition none4 = new CompositeCondition(Assert.NONE);
		// not present
		CertSubjectDNAttributeCondition subject4 = new CertSubjectDNAttributeCondition(Arrays.asList("2.5.4.4"));
		none4.addChild(subject4);

		CompositeCondition none10 = new CompositeCondition(Assert.NONE);
		// present in cert (organizationName)
		CertSubjectDNAttributeCondition subject10 = new CertSubjectDNAttributeCondition(Arrays.asList("2.5.4.10"));
		none10.addChild(subject10);

		allNones.addChild(none42);
		allNones.addChild(none65);
		allNones.addChild(none4);
		allNones.addChild(none10);

		LOG.info(allNones.toString());

		assertFalse(subject4.check(certificate));
		assertTrue(none4.check(certificate));

		assertTrue(subject10.check(certificate));
		assertFalse(none10.check(certificate));
		assertFalse(allNones.check(certificate));

		CompositeCondition allTL = new CompositeCondition(Assert.ALL);
		allTL.addChild(none42);
		allTL.addChild(none65);
		allTL.addChild(none4);
		allTL.addChild(subject10);
		assertTrue(allTL.check(certificate));

	}

}

