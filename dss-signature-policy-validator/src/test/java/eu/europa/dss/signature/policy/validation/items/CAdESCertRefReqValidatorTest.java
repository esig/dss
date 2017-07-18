package eu.europa.dss.signature.policy.validation.items;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

import eu.europa.dss.signature.policy.CertRefReq;
import eu.europa.dss.signature.policy.validation.CertificateTestUtils;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

public class CAdESCertRefReqValidatorTest {
	private static final String TEST_RESOURCES = "src/test/resources";
	
	@Test
	public void shouldValidateWhenCAdESContainsSignerOnlyWithSignerOnlyRestriction() throws Exception {
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_1.cer"));

		SignerInformation si = Mockito.mock(SignerInformation.class);
		ESSCertID ess = new ESSCertID(certificateToken.getDigest(DigestAlgorithm.SHA1), DSSASN1Utils.getIssuerSerial(certificateToken));
		ASN1Set attValues = new DERSet(new ASN1Encodable[]{new SigningCertificate(ess)});
		Attribute att = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, attValues);
		Mockito.doReturn(new AttributeTable(att)).when(si).getSignedAttributes();
		
		CAdESSignature sig = Mockito.mock(CAdESSignature.class);
		Mockito.doReturn(si).when(sig).getSignerInformation();
		Mockito.doReturn(certificateToken).when(sig).getSigningCertificateToken();
		
		CAdESCertRefReqValidator validator = new CAdESCertRefReqValidator(CertRefReq.signerOnly, sig, null);
		Assert.assertTrue("signerOnly valid", validator.validate());
	}
	
	@Test
	public void shouldValidateWhenCAdESContainsFullChainWithSignerOnlyRestriction() throws Exception {
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), new CertificatePool());
		Set<CertificateToken> fullPath = new LinkedHashSet<>();

		CertificateToken cert = certificateToken;
		ASN1EncodableVector attValuesSet = new ASN1EncodableVector();
		while (cert != null) {
			fullPath.add(cert);
			ESSCertID ess = new ESSCertID(certificateToken.getDigest(DigestAlgorithm.SHA1), DSSASN1Utils.getIssuerSerial(certificateToken));
			attValuesSet.add(new SigningCertificate(ess));
			cert = cert.getIssuerToken();
		}
		ASN1Set attValues = new DERSet(attValuesSet);

		SignerInformation si = Mockito.mock(SignerInformation.class);
		Attribute att = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, attValues);
		Mockito.doReturn(new AttributeTable(att)).when(si).getSignedAttributes();
		
		CAdESSignature sig = Mockito.mock(CAdESSignature.class);
		Mockito.doReturn(si).when(sig).getSignerInformation();
		Mockito.doReturn(certificateToken).when(sig).getSigningCertificateToken();
		
		CAdESCertRefReqValidator validator = new CAdESCertRefReqValidator(CertRefReq.signerOnly, sig, fullPath);
		Assert.assertTrue("signerOnly valid", validator.validate());
	}
	
	@Test
	public void shouldValidateWhenCAdESContainsFullChainWithFullPathRestriction() throws Exception {
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), new CertificatePool());
		Set<CertificateToken> fullPath = new LinkedHashSet<>();

		CertificateToken cert = certificateToken;
		ASN1EncodableVector attValuesSet = new ASN1EncodableVector();
		while (cert != null) {
			fullPath.add(cert);
			ESSCertID ess = new ESSCertID(cert.getDigest(DigestAlgorithm.SHA1), DSSASN1Utils.getIssuerSerial(cert));
			attValuesSet.add(new SigningCertificate(ess));
			cert = cert.getIssuerToken();
		}
		ASN1Set attValues = new DERSet(attValuesSet);

		SignerInformation si = Mockito.mock(SignerInformation.class);
		Attribute att = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, attValues);
		Mockito.doReturn(new AttributeTable(att)).when(si).getSignedAttributes();
		
		CAdESSignature sig = Mockito.mock(CAdESSignature.class);
		Mockito.doReturn(si).when(sig).getSignerInformation();
		Mockito.doReturn(certificateToken).when(sig).getSigningCertificateToken();
		
		CAdESCertRefReqValidator validator = new CAdESCertRefReqValidator(CertRefReq.fullPath, sig, fullPath);
		Assert.assertTrue("fullPath valid", validator.validate());
	}
	
	@Test
	public void shouldNotValidateWhenCAdESContainsSignerOnlyWithFullPathRestrictionAndNoChain() throws Exception {
		CertificateToken certificateToken = DSSUtils.loadCertificate(new File(TEST_RESOURCES, "BR_1.cer"));

		SignerInformation si = Mockito.mock(SignerInformation.class);
		ESSCertID ess = new ESSCertID(certificateToken.getDigest(DigestAlgorithm.SHA1), DSSASN1Utils.getIssuerSerial(certificateToken));
		ASN1Set attValues = new DERSet(new ASN1Encodable[]{new SigningCertificate(ess)});
		Attribute att = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, attValues);
		Mockito.doReturn(new AttributeTable(att)).when(si).getSignedAttributes();
		
		CAdESSignature sig = Mockito.mock(CAdESSignature.class);
		Mockito.doReturn(si).when(sig).getSignerInformation();
		Mockito.doReturn(certificateToken).when(sig).getSigningCertificateToken();
		
		CAdESCertRefReqValidator validator = new CAdESCertRefReqValidator(CertRefReq.fullPath, sig, null);
		Assert.assertFalse("fullPath invalid", validator.validate());
	}
	
	@Test
	public void shouldNotValidateWhenCAdESContainsSignerOnlyWithFullPathRestrictionAndFullChain() throws Exception {
		CertificateToken certificateToken = CertificateTestUtils.loadIssuers(new File(TEST_RESOURCES, "BR_1.cer"), new CertificatePool());
		Set<CertificateToken> fullPath = new LinkedHashSet<>();

		CertificateToken cert = certificateToken;
		while (!cert.isSelfSigned()) {
			fullPath.add(cert);
			if (!cert.isSelfSigned()) {
				cert = cert.getIssuerToken();
			}
		}

		SignerInformation si = Mockito.mock(SignerInformation.class);
		ESSCertID ess = new ESSCertID(certificateToken.getDigest(DigestAlgorithm.SHA1), DSSASN1Utils.getIssuerSerial(certificateToken));
		ASN1Set attValues = new DERSet(new ASN1Encodable[]{new SigningCertificate(ess)});
		Attribute att = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, attValues);
		Mockito.doReturn(new AttributeTable(att)).when(si).getSignedAttributes();
		
		CAdESSignature sig = Mockito.mock(CAdESSignature.class);
		Mockito.doReturn(si).when(sig).getSignerInformation();
		Mockito.doReturn(certificateToken).when(sig).getSigningCertificateToken();
		
		CAdESCertRefReqValidator validator = new CAdESCertRefReqValidator(CertRefReq.fullPath, sig, fullPath);
		Assert.assertFalse("fullPath invalid", validator.validate());
	}
}
