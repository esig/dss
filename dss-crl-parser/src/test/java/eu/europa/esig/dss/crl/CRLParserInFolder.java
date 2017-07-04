package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

@RunWith(Parameterized.class)
public class CRLParserInFolder {

	@Parameters(name = "CRL {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources");
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "crl" }, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] { file });
		}
		return dataToRun;
	}

	private CRLParser parser = new CRLParser();
	private File crl;

	public CRLParserInFolder(File crl) {
		this.crl = crl;
	}

	@Test
	public void test() throws IOException {

		try (BufferedInputStream is = new BufferedInputStream(getInputStream())) {
			CRLInfo handler = new CRLInfo();
			parser.retrieveInfo(is, handler);

			assertNotNull(handler.getCertificateListSignatureAlgorithmOid());
			assertNotNull(handler.getIssuer());
			assertNotNull(handler.getThisUpdate());
			assertNotNull(handler.getNextUpdate()); // (optional)
			assertNotNull(handler.getTbsSignatureAlgorithmOid());
			assertNotNull(handler.getSignatureValue());
		}
	}

	@Test
	public void testParseRevoked() throws IOException {
		assertNull(parser.retrieveRevocationInfo(getInputStream(), new BigInteger("111111111111111")));
	}

	private InputStream getInputStream() throws IOException {
		InputStream fis = new FileInputStream(crl);
		boolean pem = DSSUtils.isPEM(new FileInputStream(crl));
		if (pem) {
			PemReader pemReader = new PemReader(new InputStreamReader(fis));
			PemObject readPemObject = pemReader.readPemObject();
			fis = new ByteArrayInputStream(readPemObject.getContent());
			pemReader.close();
		}
		return fis;
	}

}
