package eu.europa.esig.dss.signature.policy.validation.items;

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

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.signature.policy.CertificateTrustPoint;
import eu.europa.esig.dss.signature.policy.validation.CertificateTestUtils;
import eu.europa.esig.dss.signature.policy.validation.items.CertificateTrustPointValidator;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class main goal is to try checking the trustpoint for a given certificate. The build path is generally built/retrieved in DSS so we always emulate 
 * it here by calling {@link CertificateTestUtils#loadIssuers(File, CertificatePool)} for the signer certificate.
 * @author davyd.santos
 *
 */
public class CertificateTrustPointValidatorTest {
	private static final String TEST_RESOURCES = "src/test/resources";

	@Test
	public void shouldNotBuildCertPathForDifferentTrustPoint() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "US_PIV_ROOT.cer"));
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertFalse("TrustPoint invalid (simple cert path))", validator.validate());
	}

	/*
	@Test
	public void shouldNotBuildCertPathSuccessfullyForBRWithUnmatchedNamingConstraint() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_ROOT.cer"));
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), certPool);

		ASN1Encodable forbiddenName = new X500Name("CN = DAVYD PEREIRA DO NASCIMENTO SANTOS:30773760830, OU = AR COMPROVA, OU = (EM BRANCO), OU = RFB e-CPF A3, OU = Secretaria da Receita Federal do Brasil - RFB, O = ICP-Brasil, C = BR");
		//ASN1Encodable forbiddenName = new X500Name("CN = AC SERASA RFB v2, OU = Secretaria da Receita Federal do Brasil - RFB, O = ICP-Brasil, C = BR");
		NameConstraints nameConstraints = new NameConstraints(null, new GeneralSubtree[]{new GeneralSubtree(new GeneralName(GeneralName.directoryName, forbiddenName))});
		
		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		Mockito.doReturn(nameConstraints).when(trustPoint).getNameConstraints();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertFalse("TrustPoint valid with invalid nameConstraints (simple cert path))", validator.validate());
	}*/

	@Test
	public void shouldBuildCertPathSuccessfullyForBR() throws IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CertificatePool certPool = new CertificatePool();
		CertificateToken rootCertificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_ROOT.cer"));
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
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "US_PIV_1.cer"), certPool);

		CertificateTrustPoint trustPoint = Mockito.mock(CertificateTrustPoint.class);
		Mockito.doReturn(rootCertificateToken.getCertificate()).when(trustPoint).getTrustpoint();
		Mockito.doReturn(null).when(trustPoint).getPathLenConstraint();
		Mockito.doReturn(Collections.singleton("1.1.1.1.1.1")).when(trustPoint).getAcceptablePolicySet();
		CertificateTrustPointValidator validator = new CertificateTrustPointValidator(certPool, certificateToken, trustPoint);
		Assert.assertFalse("TrustPoint with invalid AcceptablePolicySet restriction (test bridge CAs))", validator.validate());
	}
}
