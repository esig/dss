package eu.europa.dss.signature.policy.validation;

import java.util.Arrays;
import java.util.LinkedHashSet;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import eu.europa.dss.signature.policy.EnuRevReq;
import eu.europa.dss.signature.policy.RevReq;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

@RunWith(MockitoJUnitRunner.class)
public class RevReqValidatorTest {

	@Test
	public void shouldValidateReturnTrueWhenCertRevReqIsNoCheck() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.noCheck).when(revReq).getEnuRevReq();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);

		Assert.assertTrue(revReqValidator.validate());
	}

	@Test
	public void shouldValidateReturnFalseWhenCertRevReqIsOther() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.other).when(revReq).getEnuRevReq();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);

		Assert.assertFalse(revReqValidator.validate());
	}

	@Test
	public void shouldValidateReturnTrueWhenCertRevReqIsClrCheckAndCertiIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.crlCheck).when(revReq).getEnuRevReq();
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		TokenIdentifier tokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(tokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(true).when(crlToken).getStatus();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertTrue(revReqValidator.validate());
	}

	@Test
	public void shouldValidateReturnFalseWhenCertRevReqIsClrCheckAndCertIsRevoked() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.crlCheck).when(revReq).getEnuRevReq();
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		TokenIdentifier tokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(tokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(false).when(crlToken).getStatus();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertFalse(revReqValidator.validate());
	}

	@Test
	public void shouldValidateReturnTrueWhenCertRevReqIsOcspCheckAndCertiIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.ocspCheck).when(revReq).getEnuRevReq();
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		TokenIdentifier tokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(tokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doReturn(true).when(ocspToken).getStatus();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertTrue(revReqValidator.validate());
	}

	@Test
	public void shouldValidateReturnFalseWhenCertRevReqIsOcspCheckAndCertIsRevoked() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.ocspCheck).when(revReq).getEnuRevReq();
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		TokenIdentifier tokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(tokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doReturn(false).when(ocspToken).getStatus();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertFalse(revReqValidator.validate());
	}
}
