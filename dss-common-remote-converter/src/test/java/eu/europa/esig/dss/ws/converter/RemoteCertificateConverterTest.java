package eu.europa.esig.dss.ws.converter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class RemoteCertificateConverterTest {
	
	private static byte[] encodedCertificate;
	
	@BeforeClass
	public static void init() {
		String base64Certificate = "MIIC6jCCAdKgAwIBAgIGLtYU17tXMA0GCSqGSIb3DQEBCwUAMDAxGzAZBgNVBA"
				+ "MMElJvb3RTZWxmU2lnbmVkRmFrZTERMA8GA1UECgwIRFNTLXRlc3QwHhcNMTcwNjA4MTEyNjAxWhcNN"
				+ "DcwNzA0MDc1NzI0WjAoMRMwEQYDVQQDDApTaWduZXJGYWtlMREwDwYDVQQKDAhEU1MtdGVzdDCCASIw"
				+ "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMI3kZhtnipn+iiZHZ9ax8FlfE5Ow/cFwBTfAEb3R1Z"
				+ "QUp6/BQnBt7Oo0JWBtc9qkv7JUDdcBJXPV5QWS5AyMPHpqQ75Hitjsq/Fzu8eHtkKpFizcxGa9BZdkQ"
				+ "jh4rSrtO1Kjs0Rd5DQtWSgkeVCCN09kN0ZsZ0ENY+Ip8QxSmyztsStkYXdULqpwz4JEXW9vz64eTbde"
				+ "4vQJ6pjHGarJf1gQNEc2XzhmI/prXLysWNqC7lZg7PUZUTrdegABTUzYCRJ1kWBRPm4qo0LN405c94Q"
				+ "Qd45a5kTgowHzEgLnAQI28x0M3A59TKC+ieNc6VF1PsTLpUw7PNI2VstX5jAuasCAwEAAaMSMBAwDgY"
				+ "DVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQCK6LGA01TR+rmU8p6yhAi4OkDN2b1dbIL8l8"
				+ "iCMYopLCxx8xqq3ubZCOxqh1X2j6pgWzarb0b/MUix00IoUvNbFOxAW7PBZIKDLnm6LsckRxs1U32sC"
				+ "9d1LOHe3WKBNB6GZALT1ewjh7hSbWjftlmcovq+6eVGA5cvf2u/2+TkKkyHV/NR394nXrdsdpvygwyp"
				+ "EtXjetzD7UT93Nuw3xcV8VIftIvHf9LjU7h+UjGmKXG9c15eYr3SzUmv6kyOI0Bvw14PWtsWGl0QdOS"
				+ "RvIBBrP4adCnGTgjgjk9LTcO8B8FKrr+8lHGuc0bp4lIUToiUkGILXsiEeEg9WAqm+XqO";
		encodedCertificate = Utils.fromBase64(base64Certificate);
	}
	
	@Test
	public void toCertificateTokenTest() {
		RemoteCertificate remoteCertificate = new RemoteCertificate(encodedCertificate);
		CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(remoteCertificate);
		assertTrue(Arrays.equals(remoteCertificate.getEncodedCertificate(), certificateToken.getEncoded()));
	}
	
	@Test
	public void toRemoteCertificateTest() {
		CertificateToken certificateToken = DSSUtils.loadCertificate(encodedCertificate);
		RemoteCertificate remoteCertificate = RemoteCertificateConverter.toRemoteCertificate(certificateToken);
		assertTrue(Arrays.equals(remoteCertificate.getEncodedCertificate(), certificateToken.getEncoded()));
	}
	
	@Test
	public void toCertificateTokens() {
		List<RemoteCertificate> remoteCertificates = new ArrayList<RemoteCertificate>();
		remoteCertificates.add(new RemoteCertificate(encodedCertificate));
		remoteCertificates.add(new RemoteCertificate(null));
		remoteCertificates.add(null);
		List<CertificateToken> certificateTokens = RemoteCertificateConverter.toCertificateTokens(remoteCertificates);
		assertEquals(1, certificateTokens.size());
		assertTrue(Arrays.equals(certificateTokens.get(0).getEncoded(), remoteCertificates.get(0).getEncodedCertificate()));
	}

}
