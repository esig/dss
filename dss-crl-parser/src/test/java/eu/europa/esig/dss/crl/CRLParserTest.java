package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;

public class CRLParserTest {

	private CRLParser parser = new CRLParser();

	@Test(expected = IllegalArgumentException.class)
	public void illegalArgumenException() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/belgium2.crl")) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(fis, handler);
		}
	}

	@Test
	public void testBelgium2() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/belgium2.crl"); BufferedInputStream is = new BufferedInputStream(fis)) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			assertEquals("1.2.840.113549.1.1.5", handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate());

			assertEquals("1.2.840.113549.1.1.5", handler.getTbsSignatureAlgorithmOid());

			String expectedSignValueHex = "2559D78E12A24217507A4ADF992070839DC0526D3BAB446B0A337BD1297C8D90007B9990A01E5B5ED1683A9805F6CC419D1067E3F7D0DE6BF795CDE31E1140407D55EF0C42F71D006A2EA228B00750AF2D036792E1D261AFC096024953C6BD2773866F38FE2B054F9D963E7D603D2418359CDC616B135192FDCC695378DFB5E19104E26A507AD073DF1611098613806703CDB06F9CF6658BF42AC8628AC9CBB9216375E2BEE2327D034DA56601611AC118AEEFDFB6B916927805B81007203F515D5297A635DDF9904419E15FCE75539C2539EEC94DF63DECBBA2B083B2366106942183AA9F7A16FEA055DC5B0FD538E72CC835C6E194A37F73C8E04E6BDC36CE";
			byte[] signatureValue = handler.getSignatureValue();
			assertArrayEquals(Utils.fromHex(expectedSignValueHex), signatureValue);

		}
	}

	@Test
	public void testPtCRL() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/pt_crl_with_critical_extension.crl");
				BufferedInputStream is = new BufferedInputStream(fis)) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			assertEquals("1.2.840.113549.1.1.5", handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate());

			assertEquals("1.2.840.113549.1.1.5", handler.getTbsSignatureAlgorithmOid());

			String expectedSignValueHex = "1D9C9811905A3836FD9BDEC6DE27ABC18BC3DA1DB17C182EEB453A9F45D1D123C94A8FA44E3560C371CF846260AFADB62ABAB68D894B4B756383EAD77E69DF45D5193DBD6081932F39CD15A8CB92E88F1F77E8D61BA0F9F4A5FF88FACC3E486077223D94591AB994489A85DCCEAFE02244C05B321FA4675D1681E60252EAD9B34BB0473E80900593FC89AA066A205CB93EDC9F9832A0E2B344349BE6469A9A1E769C97E027D69BE6833BCD78BF892F816C6F972421680A229252648D9FB2E337B5E200127C2DD6EE293FD7CB3CD18C66464D37D629A42D1C3132ED520DE999CB64A30D583545BA2F12A0F45DC3028A27C8817F0B687B1D9192B39EB040873A410B9F804BFA6F0E9B7A55CDA29B831B6110B855F4640B06A4BA4CBAEB7F5F696A3556AD6627DD8861F463BC22E14DADB33524E8AE26FE26E332C661D3FCD67DA094A91BC5439F755F89FC5FA55F82923DF38A8FBB90E86D69C2D9E9DE8531AE98C4A8886BCDF1C95FB5183200621803F07C9088722EF68E96B5D944DF072F875D8C48FB213E1A4A52155CEC88D2722D4D8B90E92602097B2A8A94A1EB96B2ECB796B8804C8A6702B5E9B53A356706059824F59B0FD7FE843EA5818A909B44A69480BB03826A5B43804B999B8318C35FC91065982C2F7816ED1EA80BD9C1471CA1E60E619426749E95AB2DD270FC9BE43437928622C5EAC6632FEAC1BF894E70C0";
			byte[] signatureValue = handler.getSignatureValue();
			assertArrayEquals(Utils.fromHex(expectedSignValueHex), signatureValue);
		}
	}

	@Test
	public void testLTRCA() throws IOException {
		/*
		 * byte[] der = DSSUtils.convertCRLToDER(new String(Utils.toByteArray(new
		 * FileInputStream("src/test/resources/LTRCA.crl"))));
		 * 
		 * try (ByteArrayInputStream bais = new ByteArrayInputStream(der)) { CRLInfo handler = new CRLInfo();
		 * parser.retrieveInfo(bais, handler);
		 * 
		 * assertEquals("1.2.840.113549.1.1.5", handler.getCertificateListSignatureAlgorithmOid());
		 * assertNotNull(handler.getIssuer());
		 * assertNotNull(handler.getThisUpdate()); assertNotNull(handler.getNextUpdate());
		 * 
		 * assertEquals("1.2.840.113549.1.1.5", handler.getTbsSignatureAlgorithmOid());
		 * 
		 * String expectedSignValueHex =
		 * "2899EC527E9D7BB84DAE1AFFD9AABBFB669E0645CC9C50843888472376BD12FAA1FA11DBD409CCE03CC8B2E82C7599F81799B39FDFD6E171B728B00CF38C50F37882924E8A05800D2712C6F0340052F774D95D9DFBEF557A69121E89CE51B810B9E7C9481E2F35E635E8BFA097CA59F26F1F34E26F7C684A5A90553EFA3D1D08C01D97F22CFB961903D47654C887FC0B51BA6A6FBF29360D18F6F13EEA9677C3F1BB8B7EBE8F69795E6B7BC4538AB8EE76744B6FA39FC1E345B2A98A4454A5AEE677000C764806693F28AF0C64AD93FC0CCEC7D35C2235D966EC9FD6014B5EE756C211C3157B4ECF6F262F5F12787F05FE37F8FECA5BBAD058C609F0C8F559B5";
		 * byte[] signatureValue = handler.getSignatureValue(); assertArrayEquals(Utils.fromHex(expectedSignValueHex),
		 * signatureValue); }
		 */
	}

	@Test
	public void testLTGRCA() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/LTGRCA.crl"); BufferedInputStream is = new BufferedInputStream(fis)) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			assertEquals("1.2.840.113549.1.1.5", handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate());

			assertEquals("1.2.840.113549.1.1.5", handler.getTbsSignatureAlgorithmOid());

			String expectedSignValueHex = "99C1175BE7737B9F03312F97F2D7108DCFA4A7EC66A4495A985C393571E09E997B50858E6B117CA36CF05C776C1C2ED7CA2F856ABCBC710717B26D69843A5FE013F70DC292F956243685B81DD309078313D0963E5E066CDAB3BF0A3A41FA389328445EF2913AB07ABA5150AD35314C5DF383456DF9A3B8C4EFD7490830C6F7156D5C4FD0186D447A2EDC6042F52D3D96BCAD6DEA7A44EC5E8CBF352C192FBD51DF38716D74792991F4164A27CC6F781CFB7AD186D9975C05EA3D4012C668E0B1D2982F6AD43C99EAFE19B9083394EF0876EF1BEF215AA3142A7DE1618E771024075600E50652C78DD7D736D5422F61FE3EB06634FA848479C9226E03F8774075";
			byte[] signatureValue = handler.getSignatureValue();
			assertArrayEquals(Utils.fromHex(expectedSignValueHex), signatureValue);
		}
	}

	@Test
	public void testExtension() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/crl_with_expiredCertsOnCRL_extension.crl");
				BufferedInputStream is = new BufferedInputStream(fis)) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			assertEquals("1.2.840.113549.1.1.11", handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate());

			assertTrue(!handler.getCriticalExtensions().isEmpty());
			assertTrue(Utils.isArrayNotEmpty(handler.getCriticalExtension("2.5.29.28")));
			assertTrue(Utils.isArrayEmpty(handler.getNonCriticalExtension("2.5.29.28")));

			assertTrue(!handler.getNonCriticalExtensions().isEmpty());
			assertTrue(Utils.isArrayNotEmpty(handler.getNonCriticalExtension("2.5.29.60")));
			assertTrue(Utils.isArrayEmpty(handler.getCriticalExtension("2.5.29.60")));

			assertEquals("1.2.840.113549.1.1.11", handler.getTbsSignatureAlgorithmOid());

			byte[] signatureValue = handler.getSignatureValue();
			assertTrue(Utils.isArrayNotEmpty(signatureValue));
		}
	}

	@Test
	public void testHuge() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/esteid2011.crl"); BufferedInputStream is = new BufferedInputStream(fis)) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			if (handler.getVersion() != null) {
				assertEquals(2, handler.getVersion().intValue());
			}
			assertEquals("1.2.840.113549.1.1.11", handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate());

			assertEquals("1.2.840.113549.1.1.11", handler.getTbsSignatureAlgorithmOid());

			String expectedSignValueHex = "A64722EC3685353F7202971960E280F6B808A9F6AA2B253680D12EBCCEFCED7D65439FD5F62B2422062F7F1250ED11729A64291F7EACBEEA8E1F56EE2440555E5A36F8589F9FF27519B0CE6B446F4A6A42C5E0FED469577286ED3FA00DA72B066F246727BF2A114A3FA9EA5436ABC59A66FB896FB07D8A7085B7063DA510A708BA265EC724B758AE25339197895B45836C3C3E735748280DACF5E1CC55B97B491FD34A3E366F85753A36F087A15F5675A766A0BFD77ECFBDD580D9D76BAC82C303C6D6DBBA5117428FBE4702BA7D7277403D4C345E714D26F546EA0B4C91DBBA8A682D28F9506F3B55689FACFF6E87A613320CCC195883CC587E0B16B1D39776";
			byte[] signatureValue = handler.getSignatureValue();
			assertArrayEquals(Utils.fromHex(expectedSignValueHex), signatureValue);
		}
	}

	@Test
	public void retrieveRevocationInfo() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/LTGRCA.crl"); BufferedInputStream is = new BufferedInputStream(fis)) {
			BigInteger serialNumber = new BigInteger("5203");
			X509CRLEntry entry = parser.retrieveRevocationInfo(fis, serialNumber);
			assertNotNull(entry);
			assertNotNull(entry.getRevocationDate());
			assertNotNull(entry.getRevocationReason());
			assertNotNull(entry.getSerialNumber());
			assertEquals(serialNumber, entry.getSerialNumber());
		}
	}

	@Test
	public void retrieveRevocationInfoNull() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/LTGRCA.crl")) {
			BigInteger serialNumber = new BigInteger("52030000000");
			assertNull(parser.retrieveRevocationInfo(fis, serialNumber));
		}
	}

	@Test
	public void retrieveRevocationInfoMedium() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/http___crl.globalsign.com_gs_gspersonalsign2sha2g2.crl")) {

			BigInteger serialNumber = new BigInteger("288350169419475868349393253038503091234");
			X509CRLEntry entry = parser.retrieveRevocationInfo(fis, serialNumber);
			assertNotNull(entry);
			assertNotNull(entry.getRevocationDate());
			assertNull(entry.getRevocationReason());
			assertNotNull(entry.getSerialNumber());
			assertEquals(serialNumber, entry.getSerialNumber());
		}
	}

	@Test
	public void retrieveRevocationInfoMediumLastEntry() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/http___crl.globalsign.com_gs_gspersonalsign2sha2g2.crl")) {

			BigInteger serialNumber = new BigInteger("288350169419475868349393264025423631520");
			X509CRLEntry entry = parser.retrieveRevocationInfo(fis, serialNumber);
			assertNotNull(entry);
			assertNotNull(entry.getRevocationDate());
			assertNull(entry.getRevocationReason());
			assertNotNull(entry.getSerialNumber());
			assertEquals(serialNumber, entry.getSerialNumber());
		}
	}

	@Test
	public void retrieveRevocationInfoHuge() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/esteid2011.crl")) {
			BigInteger serialNumber = new BigInteger("1111111111111111111");
			assertNull(parser.retrieveRevocationInfo(fis, serialNumber));
		}
	}
}
