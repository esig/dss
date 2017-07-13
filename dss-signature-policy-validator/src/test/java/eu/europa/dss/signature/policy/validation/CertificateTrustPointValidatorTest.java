package eu.europa.dss.signature.policy.validation;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import eu.europa.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateTrustPointValidatorTest {
	private static final String TEST_RESOURCES = "src/test/resources";

	@Test
	public void shouldBuildCertPathSuccessfullyForBR() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_ROOT.cer"));
		rootCertificateToken = certPool.getInstance(rootCertificateToken, CertificateSourceType.TRUSTED_STORE);
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertTrue("TrustPoint valid (simple cert path))", validator.validate());
	}

	@Test
	public void shouldBuildCertPathSuccessfullyForBRWithPolicyRestriction() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_ROOT.cer"));
		rootCertificateToken = certPool.getInstance(rootCertificateToken, CertificateSourceType.TRUSTED_STORE);
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		Mockito.doReturn(new LinkedHashSet<String>(Arrays.asList("2.16.76.1.2.3.1", "2.16.76.1.2.3.10"))).when(trustPoint).getAcceptablePolicySet();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertTrue("TrustPoint valid with policy restriction (simple cert path))", validator.validate());
	}

	@Test
	public void shouldBuildCertPathSuccessfullyForPIV() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "US_PIV_ROOT.cer"));
		rootCertificateToken = certPool.getInstance(rootCertificateToken, CertificateSourceType.TRUSTED_STORE);
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "US_PIV_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertTrue("TrustPoint valid (test bridge CAs))", validator.validate());
	}

	@Test
	public void shouldNotBuildCertPathSuccessfullyForPIVAndMaxLengthLowerThanNecessary() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "US_PIV_ROOT.cer"));
		rootCertificateToken = certPool.getInstance(rootCertificateToken, CertificateSourceType.TRUSTED_STORE);
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "US_PIV_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(1).when(trustPoint).getPathLenConstraint();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertFalse("TrustPoint with invalid PathLenConstraint (test bridge CAs))", validator.validate());
	}

	@Test
	public void shouldNotBuildCertPathSuccessfullyForPIVAndDifferentPolicy() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "US_PIV_ROOT.cer"));
		rootCertificateToken = certPool.getInstance(rootCertificateToken, CertificateSourceType.TRUSTED_STORE);
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "US_PIV_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		Mockito.doReturn(Collections.singleton("1.1.1.1.1.1")).when(trustPoint).getAcceptablePolicySet();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertFalse("TrustPoint with invalid AcceptablePolicySet restriction (test bridge CAs))", validator.validate());
	}
}
