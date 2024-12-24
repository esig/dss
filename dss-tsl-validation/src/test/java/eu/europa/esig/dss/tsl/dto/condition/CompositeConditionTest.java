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

class CompositeConditionTest {

	private static final Logger LOG = LoggerFactory.getLogger(CompositeConditionTest.class);

	private CertificateToken certificate = DSSUtils.loadCertificateFromBase64EncodedString(
			"MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");

	@Test
	void testDefault() {
		CompositeCondition condition = new CompositeCondition();
		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString())));

		LOG.info(condition.toString());
		assertTrue(condition.check(certificate));

		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.EmailAddress.toString())));
		LOG.info(condition.toString());
		assertFalse(condition.check(certificate));
	}

	@Test
	void testAll() {
		CompositeCondition condition = new CompositeCondition(Assert.ALL);
		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString())));

		LOG.info(condition.toString());
		assertTrue(condition.check(certificate));

		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.EmailAddress.toString())));
		LOG.info(condition.toString());
		assertFalse(condition.check(certificate));
	}

	@Test
	void testAtLeastOne() {
		CompositeCondition condition = new CompositeCondition(Assert.AT_LEAST_ONE);
		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString())));

		LOG.info(condition.toString());
		assertTrue(condition.check(certificate));

		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.EmailAddress.toString())));
		LOG.info(condition.toString());
		assertTrue(condition.check(certificate));
	}

	@Test
	void testNone() {
		CompositeCondition condition = new CompositeCondition(Assert.NONE);
		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString())));

		LOG.info(condition.toString());
		assertFalse(condition.check(certificate));

		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.EmailAddress.toString())));
		LOG.info(condition.toString());
		assertFalse(condition.check(certificate));
	}

	@Test
	void testMultiComposites() {

		CompositeCondition condition = new CompositeCondition(Assert.ALL);
		condition.addChild(new CertSubjectDNAttributeCondition(Arrays.asList(BCStyle.C.toString())));

		CompositeCondition subCondition = new CompositeCondition(Assert.ALL);
		subCondition.addChild(new ExtendedKeyUsageCondition(Arrays.asList("1.3.6.1.5.5.7.3.9")));

		CompositeCondition subSubCondition = new CompositeCondition(Assert.NONE);
		subSubCondition.addChild(new ExtendedKeyUsageCondition(Arrays.asList("1.3.1")));

		subCondition.addChild(subSubCondition);

		condition.addChild(subCondition);

		LOG.info(condition.toString());

		assertTrue(condition.check(certificate));
	}
}
