package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.x509.CertificateToken;

public class MultiThreadsCertificateValidatorTest {

	@Test
	public void test() throws InterruptedException, ExecutionException {

		ExecutorService executor = Executors.newFixedThreadPool(50);

		List<Future<CertificateReports>> futures = new ArrayList<Future<CertificateReports>>();

		for (int i = 0; i < 1000; i++) {
			futures.add(executor.submit(new TestConcurrent(DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt")))));
		}

		for (Future<CertificateReports> future : futures) {
			CertificateReports certificateReports = future.get();
			assertNotNull(certificateReports);
			DiagnosticData diagnosticData = certificateReports.getDiagnosticData();
			assertNotNull(diagnosticData);
		}

		executor.shutdown();

	}

	class TestConcurrent implements Callable<CertificateReports> {

		private final CertificateToken certificate;

		public TestConcurrent(CertificateToken certificate) {
			this.certificate = certificate;
		}

		@SuppressWarnings("serial")
		@Override
		public CertificateReports call() throws Exception {
			CertificateValidator cv = CertificateValidator.fromCertificate(certificate);
			CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

			// cache for AIA
			certificateVerifier.setDataLoader(new DataLoader() {

				@Override
				public byte[] get(String url) {
					if ("http://ca.luxtrust.lu/LTQCA.crt".equals(url)) {
						return Utils.fromBase64(
								"MIID8DCCAtigAwIBAgICA+swDQYJKoZIhvcNAQEFBQAwQDELMAkGA1UEBhMCTFUxFjAUBgNVBAoTDUx1eFRydXN0IHMuYS4xGTAXBgNVBAMTEEx1eFRydXN0IHJvb3QgQ0EwHhcNMDgwNjA1MDkyNTI0WhcNMTYxMDE4MTA0MDM0WjBFMQswCQYDVQQGEwJMVTEWMBQGA1UEChMNTHV4VHJ1c3QgUy5BLjEeMBwGA1UEAxMVTHV4VHJ1c3QgUXVhbGlmaWVkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAybFXzA+8RNnvlCd+sZ8BnH6WO3LmaLi419Ygd9VBYcIwLmMx9KgAKF3u4B87Hee5NL4Xvhm/B9DuDUH5OGZ3P2Dwf7putVEvATvW8jzYq6CzarUthzb9ux+KTdTT+d4y6tkgVggy9DBe+bz635oZm2PPQT9kzoR48RBN730KA/MJIa0Sa7ZDphL37WHSA4/TWh9F1/LBRVGC0F4Mg1hU/u+kovF5mTuUK+ncU7+FS0cQRhAD+C4WfLI/WuzuE+T6ZuZ6Iqg6+vqgf6iKwL6iVZmwKkJPvV3+3Wgy3zq5tpDvsIGj4kXd1riQGKsEeDfN8y71DG3OdBqF1Yd7ue7ziwIDAQABo4HuMIHrMA8GA1UdEwQIMAYBAf8CAQAwQgYDVR0gBDswOTA3BggrgSsBAQEBADArMCkGCCsGAQUFBwIBFh1odHRwOi8vcmVwb3NpdG9yeS5sdXh0cnVzdC5sdTARBglghkgBhvhCAQEEBAMCAAcwDgYDVR0PAQH/BAQDAgHGMB8GA1UdIwQYMBaAFN2K1zDx+ZFx6UdwDCXlrKGN34wlMDEGA1UdHwQqMCgwJqAkoCKGIGh0dHA6Ly9jcmwubHV4dHJ1c3QubHUvTFRSQ0EuY3JsMB0GA1UdDgQWBBSNkKMH3RoTd5lMkqtNQ94/zSlkBTANBgkqhkiG9w0BAQUFAAOCAQEAapxOpigXTejGgHBWMAwDBMdZQHpPyoCmw32OIj1qqezO5nDnjG5gfJni/rp5IFMpV//xmCkjqyO92PyYbcHNSUpP1SjCkyn10e6ipmzpXK0MbgFvIPglAgA5dXxTNf0Q77eWu36fz5VKQEmJzqoXTccq4nuLL9rLZ88YUlczMaWscETIZCB4kecKVyqHf4+T0JucZqX7zzfpiVyTr2M+OGl9qiOmKwBGkzseJt+MgYWrskJADKDZMr4bQxkxnhzCSQoraX7DugxM0fH47MitCc74uZrWIJ6qQjCLBtKzxUGy7B3pYOjLlThr7S64cd12yuR+NjHAFZ2DTXwxKg/FQg==");
					}
					return null;
				}

				@Override
				public DataAndUrl get(List<String> urlStrings) {
					throw new DSSException("Not implemented");
				}

				@Override
				public byte[] get(String url, boolean refresh) {
					throw new DSSException("Not implemented");
				}

				@Override
				public byte[] post(String url, byte[] content) {
					throw new DSSException("Not implemented");
				}

				@Override
				public void setContentType(String contentType) {
					throw new DSSException("Not implemented");
				}

			});

			cv.setCertificateVerifier(certificateVerifier);
			return cv.validate();
		}

	}

}
