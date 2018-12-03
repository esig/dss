/**
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
 */
package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.client.http.MemoryDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;

public class DSS1496Test extends PKIFactoryAccess {

	private static final String TRUST_ANCHOR = "MIIFwTCCA6mgAwIBAgIQdLjPY4+rcrxGwdK6zQAFDDANBgkqhkiG9w0BAQ0FADBzMRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQ0wCwYDVQQLEwREQ0ZEMQ8wDQYDVQQKEwZNSUNJVFQxCzAJBgNVBAYTAkNSMSkwJwYDVQQDEyBDQSBSQUlaIE5BQ0lPTkFMIC0gQ09TVEEgUklDQSB2MjAeFw0xNTAyMjQyMjE5NTVaFw0zOTAyMjQyMjI4NDRaMHMxGTAXBgNVBAUTEENQSi0yLTEwMC0wOTgzMTExDTALBgNVBAsTBERDRkQxDzANBgNVBAoTBk1JQ0lUVDELMAkGA1UEBhMCQ1IxKTAnBgNVBAMTIENBIFJBSVogTkFDSU9OQUwgLSBDT1NUQSBSSUNBIHYyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwnQxZdkRRU4vV9xiuV3HStB/7o3GB95pZL/NgdVXrSc+X1hxGtwgwPyrc/SrLodUpXBYWD0zQNSQWkPpXkRoSa7guAjyHDpmfDkbRk2Oj414OpN3Etoehrw9pBWgHrFK1e5+oj2iHj1QRBUPlcyKJTz+DyOgvY2wC5Tgyxj4Fn2Tqy79Ck6UlerJgp8xRbPJwuF/2apBlzXu+/zvV3Pv2MMrPvSMpVK0oAw47TLpSzNRG3Z88V9PhPdkEyvqstdWQHiuFp49ulRvsr1cRdmkNptO0q6udPyej3k50Dl8IzhW1Uv5yPCKpxpDpoyy3X6HnfmZ470lbhzTZ12AQ392ansLLnO/ZOT4E9JB1M2UiZox8TdGe5RKDNQGK2GWJIQKDsIZqcVCmbGrCRPxCOtC/NwILxQCu8k1TkeH8SlrkwiBMsoCu5qeNrkarQxEYcVNXyw0rAaofaNL/42a5x7ulg78bNFBMj3vXM81WyFt+K3Ef+Zzd94ib/iOuzajKCIxiI+lp0PaNiVgj4a3h5BJM74umhCv0U+TAqIljp5QqPJvikcT4PgU4OS9/kCNxpKYqHJzRoijHWeA+EOSlAnuztya9KQLzmzoC/gQ4hqVfk2UNQ57DKdkuPbBTFvCSTjzRV+J7lfpci+WhT1BCRgUKSIwGEHYOm1dvjWOydRQBzcCAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFODy/n3ERE5Q5DX9CImPToQZRDNAMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBDQUAA4ICAQBJ5nSJMjsLLttbQWOESI3JjGtP7LIEIQCMAjM7WJTmUDMK1Xd+LKGq/vMzv0OnlCVsM4D7pnpWyEU30n9BvwCk4/bcp/ka/NBbE0fXNVF2px0T369RmfSBR32+y67kwfV9wT2lsm1M6faOCtLXgOe0UaCD5shbegU8RQhk2owSQTj6ZeXKQSnr5dv6z4nE5hFUFCMWYvbO9Lq9EyzzzMOEbV4fOu9PVgPQ5wARzJ0pf0evH9SnId5Y1nvSAYkHPgoiqiaSlcy9nN2C+QHwvt89nIH4krkSp0bLjX7ww8UgSzJnmrwWrjqt0c+OpOEkBlkmz2WeRK6G7fvov8SFSjZkMaiAKRHbxAuDSs+HAG9xzrI7OjvaLuVq5w0r3p77XT70Hiv6M/8ysMP3FpjNcK8xHjtOupjqVhK+KqBAhC8Z7fIyPH8U2vXPexCO449G930dnK4S8S6CpCh4bdRuZg/n+vRa9Cf/GheO56aANt+unoPf1tfYhKcFGx40lSBxoQtx6eR8TMhuQBJBwd4IRG/cy6ysE0vF2WKikc+m7a8vJYk+Did3n3nHKFKABh0Fdf6Id1/KiyXO0ivm1xR7uK0mreiETRcWa7Pw2D1NllnuoIyx1gsc0eYmZnZC5lV7VBt1xfpCyaRtmcqU7Jzvk/rl9U8rMSpaOcySGf15dGPVtQ==";

	private static final String TSA_CA_URL = "http://www.firmadigital.go.cr/repositorio/CA%20POLITICA%20SELLADO%20DE%20TIEMPO%20-%20COSTA%20RICA%20v2.crt";
	private static final String TSA_CA = "MIILkzCCCXugAwIBAgITTgAAAASYOR/4A7hb3AAAAAAABDANBgkqhkiG9w0BAQ0FADBzMRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQ0wCwYDVQQLEwREQ0ZEMQ8wDQYDVQQKEwZNSUNJVFQxCzAJBgNVBAYTAkNSMSkwJwYDVQQDEyBDQSBSQUlaIE5BQ0lPTkFMIC0gQ09TVEEgUklDQSB2MjAeFw0xNTAyMjUyMTQ3NDNaFw0zMTAyMjUyMTU3NDNaMIGAMRkwFwYDVQQFExBDUEotMi0xMDAtMDk4MzExMQswCQYDVQQGEwJDUjEPMA0GA1UEChMGTUlDSVRUMQ0wCwYDVQQLEwREQ0ZEMTYwNAYDVQQDEy1DQSBQT0xJVElDQSBTRUxMQURPIERFIFRJRU1QTyAtIENPU1RBIFJJQ0EgdjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2m5S5sYbQiWTklYT8+i9PCNAXS/Mw/TByDhY7zNP7WyJtPSUnSbQRLdQ3hMPuJ6iVgoZWNKx1TJ7MzNVPOv713eEcqqDm69XWSSaQJEz3HbTAVC23V3PJcEuuQfJuKZ+7YP2VMMhBj73UoJdQqMx3nJpECJDjzCrCZHEPtusDRa1+CEmm61ghSDKwUvjow98rkuBvu837MWb3iDj9y8KbbKvme4CPRiAnmZv9N8H5q1zrO6EmWX46+z4ofkUji7flDLzVxCG9b3irrGf7ig+IzfXBBqyr/OLNg32xKZNdezbSKDRsjHxQMpeS6vHu+spOPK65ujLhjTLNHF5v31x+fFPiz++Iz1DoUfTpEz/GlB3Z6HceP2eKgghwOrEgzZ9sT+l0aGxolASLeiiyW73TWyuL1ubRPaJV41ZfFzgZcb7b/LDei31claIEm+OMPEF1s5dfjsAByXqQCl0UUuTYqaBT8N8OC7qh/KZYQx4jbdgl2vvgR/bnaD1VO6AEbySBHW7sG1XgDkjKsPZr2EtnacZ6pdAlAI69pYPabwOo5wvJhKhFXh3ymhV5JNThCpbqGX+7x1eL8eTfelvsbmmnZtS5+Rtol9bsSLG/BAwhNHJmFHvnbper5cHJ4TPmz+k0aveKM2i+yGeRcp/0N5ZOKoWCia4apU7RcBZnTFVFfQIDAQABo4IGEDCCBgwwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFLC74AguSxNo8NCARANnpD//JWP2MIIDvwYDVR0gBIIDtjCCA7IwggEUBgdggTwBAQEBMIIBBzCBpgYIKwYBBQUHAgIwgZkegZYASQBtAHAAbABlAG0AZQBuAHQAYQAgAGwAYQAgAFAAbwBsAGkAdABpAGMAYQAgAGQAZQAgAGwAYQAgAFIAYQBpAHoAIABDAG8AcwB0AGEAcgByAGkAYwBlAG4AcwBlACAAZABlACAAQwBlAHIAdABpAGYAaQBjAGEAYwBpAG8AbgAgAEQAaQBnAGkAdABhAGwAIAB2ADIwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cuZmlybWFkaWdpdGFsLmdvLmNyADAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5taWNpdC5nby5jci9maXJtYWRpZ2l0YWwAMIIBWwYIYIE8AQEBAQEwggFNMIHsBggrBgEFBQcCAjCB3x6B3ABJAG0AcABsAGUAbQBlAG4AdABhACAAbABhACAAUABvAGwAaQB0AGkAYwBhACAAYwBvAG0AbwAgAEMAQQAgAEUAbQBpAHMAbwByAGEAIABwAGEAcgBhACAAUwBlAGwAbABhAGQAbwAgAGQAZQAgAFQAaQBlAG0AcABvACAAcABlAHIAdABlAG4AZQBjAGkAZQBuAHQAZQAgAGEAIABsAGEAIABQAEsASQAgAE4AYQBjAGkAbwBuAGEAbAAgAGQAZQAgAEMAbwBzAHQAYQAgAFIAaQBjAGEAIAB2ADIwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cuZmlybWFkaWdpdGFsLmdvLmNyADAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5taWNpdC5nby5jci9maXJtYWRpZ2l0YWwAMIIBNwYIYIE8AQEBAQUwggEpMIHIBggrBgEFBQcCAjCBux6BuABJAG0AcABsAGUAbQBlAG4AdABhACAAbABhACAAUABvAGwAaQB0AGkAYwBhACAAZABlACAAUwBlAGwAbABhAGQAbwAgAGQAZQAgAFQAaQBlAG0AcABvACAAZABlAGwAIABTAGkAcwB0AGUAbQBhACAATgBhAGMAaQBvAG4AYQBsACAAZABlACAAQwBlAHIAdABpAGYAaQBjAGEAYwBpAG8AbgAgAEQAaQBnAGkAdABhAGwAIAB2ADIwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cuZmlybWFkaWdpdGFsLmdvLmNyADAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5taWNpdC5nby5jci9maXJtYWRpZ2l0YWwAMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFODy/n3ERE5Q5DX9CImPToQZRDNAMIHSBgNVHR8EgcowgccwgcSggcGggb6GWmh0dHA6Ly93d3cuZmlybWFkaWdpdGFsLmdvLmNyL3JlcG9zaXRvcmlvL0NBJTIwUkFJWiUyME5BQ0lPTkFMJTIwLSUyMENPU1RBJTIwUklDQSUyMHYyLmNybIZgaHR0cDovL3d3dy5taWNpdC5nby5jci9maXJtYWRpZ2l0YWwvcmVwb3NpdG9yaW8vQ0ElMjBSQUlaJTIwTkFDSU9OQUwlMjAtJTIwQ09TVEElMjBSSUNBJTIwdjIuY3JsMIHmBggrBgEFBQcBAQSB2TCB1jBmBggrBgEFBQcwAoZaaHR0cDovL3d3dy5maXJtYWRpZ2l0YWwuZ28uY3IvcmVwb3NpdG9yaW8vQ0ElMjBSQUlaJTIwTkFDSU9OQUwlMjAtJTIwQ09TVEElMjBSSUNBJTIwdjIuY3J0MGwGCCsGAQUFBzAChmBodHRwOi8vd3d3Lm1pY2l0LmdvLmNyL2Zpcm1hZGlnaXRhbC9yZXBvc2l0b3Jpby9DQSUyMFJBSVolMjBOQUNJT05BTCUyMC0lMjBDT1NUQSUyMFJJQ0ElMjB2Mi5jcnQwDQYJKoZIhvcNAQENBQADggIBADnF0LdoBRhNynIHrWcNmRTmX3HqQBdO7rIIqhZvDdfVj/Ew2Io73K/eW3DRI28HmV545pRKxU5lKeZy7szI+W8+ZTApBGZgQErw5Klfk20b2bul15OEYphIz3d1NC2lQG5PggpO9KQtHEMeGCDx569UKsYekBaWfz7q7V7a+k4xFGKJFNyKQP0HAsmpfLSuJvqRrEORuQpNRxGzljIF3N1VTwzFTnW2sH7DBVoH3a/Viggs8BXqBpp2bqdfUJKiwgCmY//9fBP1zLiyEKthG1lKmzs06OdjmWeqL/6QBlfBbQtecqrfHIfJAnkwsIGXGLd39cM0jAZFnENl2z5unJnHdCLnxro/ct06E7bYJ4MJcWA9s4IrDREHjSAO4PczDzE0W/a0cpGDdYGvXIuH3qRV1LutTmecxC5+mALhBEWV1JAAr0W7LAWTRBtwjHNas9AVxb4SOGbtEV9jabics2QqNU08PiMROjuM/qnKACR5euRZG6k8eP7ft1n3ufHmP9FpPz5jWF37m4ciVm/3VJTA/RvBkzwGFdISOyOUx0Ei4wx8z2MeGaa0ZEhY7kwOugT6Jsi/npc/tVcDxCo35g4cz47tFkY4r2hoUTPqvrlStanbwdI5xD3P3j2Z7rVwal+R/Nx3Ma6EP+mf73m8w+KdZHrQbL/oXIB9A/GW+roN";

	@Test
	public void test() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/doc-firmado.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(getTrustedCertSource());
		// Offline
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// Not LTA, missing certs,...
		assertEquals(SignatureLevel.PAdES_BASELINE_T.toString(), signatureWrapper.getSignatureFormat());
	}

	@Test
	public void testLT() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/doc-firmado-LT.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(getTrustedCertSource());
		// Offline
		certificateVerifier.setDataLoader(new IgnoreDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PAdES_BASELINE_LT.toString(), signatureWrapper.getSignatureFormat());

		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertEquals(3, timestampWrapper.getCertificateChain().size());
	}

	@Ignore
	public void testExtendLT() throws Exception {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/doc-firmado-T.pdf"));

		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(getTrustedCertSource());

		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();
		dataMap.put(TSA_CA_URL, Utils.fromBase64(TSA_CA));
		DataLoader dataLoader = new MemoryDataLoader(dataMap);
		certificateVerifier.setDataLoader(dataLoader);

		certificateVerifier.setCrlSource(new OnlineCRLSource());
		certificateVerifier.setOcspSource(new OnlineOCSPSource());

		PAdESService service = new PAdESService(certificateVerifier);
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
		DSSDocument extendDocument = service.extendDocument(dssDocument, parameters);

		extendDocument.save("target/doc-firmado-LT.pdf");

	}

	private CertificateSource getTrustedCertSource() {
		CertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(TRUST_ANCHOR));
		return trustedCertSource;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
