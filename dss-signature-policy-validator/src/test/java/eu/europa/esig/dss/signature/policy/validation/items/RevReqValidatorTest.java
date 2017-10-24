/*******************************************************************************
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.Arrays;
import java.util.LinkedHashSet;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.TokenIdentifier;
import eu.europa.esig.dss.signature.policy.EnuRevReq;
import eu.europa.esig.dss.signature.policy.RevReq;
import eu.europa.esig.dss.signature.policy.validation.items.RevReqValidator;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

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
		Mockito.doReturn(true).when(crlToken).isValid();
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
		Mockito.doReturn(true).when(crlToken).isValid();
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
		Mockito.doReturn(true).when(ocspToken).isValid();
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
		Mockito.doReturn(true).when(ocspToken).isValid();
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertFalse(revReqValidator.validate());
	}
	
	@Test
	public void shouldValidateReturnFalseWhenCertRevReqIsEitherCheckAndOcspIsRevokedAndCrlIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.eitherCheck).when(revReq).getEnuRevReq();
		
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		Mockito.doReturn("ocsp".getBytes()).when(ocspToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier ocspTokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(ocspTokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doReturn(false).when(ocspToken).getStatus();
		Mockito.doReturn(true).when(ocspToken).isValid();
		
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		Mockito.doReturn("crl".getBytes()).when(crlToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier crlTokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(crlTokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(true).when(crlToken).getStatus();
		Mockito.doReturn(true).when(crlToken).isValid();
		
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken, crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertFalse(revReqValidator.validate());
	}
	
	@Test
	public void shouldValidateReturnTrueWhenCertRevReqIsEitherCheckAndOcspThrowsExceptionAndCrlIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.eitherCheck).when(revReq).getEnuRevReq();
		
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		Mockito.doReturn("ocsp".getBytes()).when(ocspToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier ocspTokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(ocspTokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doThrow(new DSSException()).when(ocspToken).getStatus();
		Mockito.doReturn(true).when(ocspToken).isValid();
		
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		Mockito.doReturn("crl".getBytes()).when(crlToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier crlTokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(crlTokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(true).when(crlToken).getStatus();
		Mockito.doReturn(true).when(crlToken).isValid();
		
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken, crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertTrue(revReqValidator.validate());
	}
	
	@Test
	public void shouldValidateReturnFalseWhenCertRevReqIsBothCheckAndOcspThrowsExceptionAndCrlIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.bothCheck).when(revReq).getEnuRevReq();
		
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		Mockito.doReturn("ocsp".getBytes()).when(ocspToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier ocspTokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(ocspTokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doThrow(new DSSException()).when(ocspToken).getStatus();
		Mockito.doReturn(true).when(ocspToken).isValid();
		
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		Mockito.doReturn("crl".getBytes()).when(crlToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier crlTokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(crlTokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(true).when(crlToken).getStatus();
		Mockito.doReturn(true).when(crlToken).isValid();
		
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken, crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertFalse(revReqValidator.validate());
	}
	
	@Test
	public void shouldValidateReturnTrueWhenCertRevReqIsBothCheckAndOcspIsOkAndCrlIsOk() throws Exception {
		RevReq revReq = Mockito.mock(RevReq.class);
		Mockito.doReturn(EnuRevReq.bothCheck).when(revReq).getEnuRevReq();
		
		OCSPToken ocspToken = Mockito.mock(OCSPToken.class);
		Mockito.doReturn("ocsp".getBytes()).when(ocspToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier ocspTokenIdentifier = new TokenIdentifier(ocspToken);
		Mockito.doReturn(ocspTokenIdentifier).when(ocspToken).getDSSId();
		Mockito.doReturn(true).when(ocspToken).getStatus();
		Mockito.doReturn(true).when(ocspToken).isValid();
		
		CRLToken crlToken = Mockito.mock(CRLToken.class);
		Mockito.doReturn("crl".getBytes()).when(crlToken).getDigest(DigestAlgorithm.SHA256);
		TokenIdentifier crlTokenIdentifier = new TokenIdentifier(crlToken);
		Mockito.doReturn(crlTokenIdentifier).when(crlToken).getDSSId();
		Mockito.doReturn(true).when(crlToken).getStatus();
		Mockito.doReturn(true).when(crlToken).isValid();
		
		CertificateToken certificateToken = Mockito.mock(CertificateToken.class);		
		Mockito.doReturn(new LinkedHashSet<RevocationToken>(Arrays.asList(ocspToken, crlToken))).when(certificateToken).getRevocationTokens();
		
		RevReqValidator revReqValidator = new RevReqValidator(revReq, certificateToken);
		
		Assert.assertTrue(revReqValidator.validate());
	}
}
